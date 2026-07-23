//! The QUIC endpoint, and why it is QUIC.
//!
//! # One connection, two delivery guarantees
//!
//! Input has two kinds of traffic with opposite needs. A key transition is a
//! **state edge**: losing one desynchronises the receiver's held set, which is
//! the stuck-modifier bug arriving through the transport layer. Pointer motion
//! is an **increment**: losing one costs a few pixels nobody perceives, and
//! retransmitting a 40 millisecond old delta is worse than dropping it.
//!
//! QUIC carries both on one connection. Transitions ride a reliable stream,
//! motion rides datagrams, and neither blocks the other. TCP could not do this,
//! which is why Deskflow's head-of-line blocking is a structural handicap rather
//! than a tuning problem. Plain DTLS, which lan-mouse uses, gives only the
//! datagram half and leaves everything else to be hand-rolled.
//!
//! # Cost
//!
//! Round-trip time on gigabit is 0.2 to 0.5 milliseconds. The budget is p50 at
//! or under 2 milliseconds and p99 at or under 8, derived in
//! `research/04-latency-budget.md`, so the transport must not add buffering of
//! its own. Hence datagrams, no congestion-controlled stream for motion, and a
//! keepalive short enough that a dead peer is noticed before the receiver's
//! watchdog has to guess.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::net::identity::{Credentials, Identity};
use crate::net::verify::{PinnedVerifier, TrustedPeers};

/// The port Wraith listens on by default.
///
/// Deliberately not Deskflow's 24800. Wraith speaks a different protocol, and
/// sharing a port would mean two incompatible things answering the same door.
pub const DEFAULT_PORT: u16 = 24810;

/// The port a pairing offer listens on.
///
/// Separate from [`DEFAULT_PORT`] because the two endpoints have opposite trust
/// rules and one socket cannot hold both: a quinn `Endpoint` has a single
/// verifier, the session endpoint pins identity keys and refuses everything
/// else, and the pairing endpoint has to accept a machine it has never seen,
/// because establishing that is what pairing is for.
///
/// Sharing the number also meant you could not pair while sharing, which is the
/// ordinary case rather than the exotic one: adding a third machine to a desk
/// that is already working.
pub const DEFAULT_PAIR_PORT: u16 = DEFAULT_PORT + 1;

/// How often an idle connection is probed.
///
/// Short enough that a dead peer is noticed and the connection closed before the
/// receiver's 900 millisecond idle watchdog has to fire. The watchdog is the
/// backstop; this is what usually gets there first.
const KEEPALIVE_MS: u64 = 250;

/// How long without a response before the connection is considered dead.
///
/// Must stay below the receiver's `idle_release_ms`, so a vanished peer is
/// noticed by the transport and released explicitly rather than being caught by
/// the watchdog. The watchdog still covers the case where the connection is
/// alive but the sender has stopped saying anything, which is why both exist.
/// `the_keepalive_beats_the_receiver_watchdog` holds this ordering.
const IDLE_TIMEOUT_MS: u64 = 600;

/// The protocol identifier, negotiated during the handshake.
///
/// Versioned, so a future incompatible Wraith fails the handshake cleanly rather
/// than connecting and then misinterpreting each other's frames.
const ALPN: &[u8] = b"wraith/1";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    #[error("cannot build the TLS configuration: {0}")]
    Tls(String),

    #[error("cannot bind to {address}: {source}")]
    Bind {
        address: SocketAddr,
        source: std::io::Error,
    },
}

/// Transport tuning shared by both directions.
///
/// The datagram path is what carries motion, so a peer that negotiated it away
/// would silently fall back to nothing. `max_datagram_size` staying at the
/// default is deliberate: a Wraith datagram is tens of bytes and will never
/// approach the MTU.
fn transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();

    transport.keep_alive_interval(Some(Duration::from_millis(KEEPALIVE_MS)));
    transport.max_idle_timeout(Some(
        Duration::from_millis(IDLE_TIMEOUT_MS)
            .try_into()
            .expect("a one second idle timeout is representable"),
    ));

    Arc::new(transport)
}

fn rustls_credentials(
    credentials: &Credentials,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(credentials.certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(credentials.key_der.to_vec())),
    )
}

/// A listening endpoint that accepts only paired peers.
pub fn server(
    identity: &Identity,
    trusted: TrustedPeers,
    address: SocketAddr,
) -> Result<Endpoint, EndpointError> {
    let credentials = identity
        .certificate()
        .map_err(|error| EndpointError::Tls(error.to_string()))?;
    let (chain, key) = rustls_credentials(&credentials);

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| EndpointError::Tls(error.to_string()))?
    // Mutual authentication, always. A client that presents no certificate is
    // refused rather than admitted as anonymous, which is the defect behind
    // CVE-2021-42072.
    .with_client_cert_verifier(Arc::new(PinnedVerifier::new(trusted)))
    .with_single_cert(chain, key)
    .map_err(|error| EndpointError::Tls(error.to_string()))?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic =
        QuicServerConfig::try_from(tls).map_err(|error| EndpointError::Tls(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport_config());

    Endpoint::server(config, address).map_err(|source| EndpointError::Bind { address, source })
}

/// A dialling endpoint that trusts only paired peers.
pub fn client(identity: &Identity, trusted: TrustedPeers) -> Result<Endpoint, EndpointError> {
    let credentials = identity
        .certificate()
        .map_err(|error| EndpointError::Tls(error.to_string()))?;
    let (chain, key) = rustls_credentials(&credentials);

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| EndpointError::Tls(error.to_string()))?
    .dangerous()
    // "Dangerous" in rustls' vocabulary means "you are replacing the web PKI",
    // which is exactly the intent. There is no certificate authority here, and a
    // hostname means nothing when identity is a key.
    .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(trusted)))
    .with_client_auth_cert(chain, key)
    .map_err(|error| EndpointError::Tls(error.to_string()))?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic =
        QuicClientConfig::try_from(tls).map_err(|error| EndpointError::Tls(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(transport_config());

    // Binding to an unspecified address lets the OS choose the port, which is
    // right for a dialler: nothing needs to reach it at a known address.
    let bind: SocketAddr = if address_is_ipv6(address_hint()) {
        "[::]:0".parse().expect("a valid bind address")
    } else {
        "0.0.0.0:0".parse().expect("a valid bind address")
    };

    let mut endpoint = Endpoint::client(bind).map_err(|source| EndpointError::Bind {
        address: bind,
        source,
    })?;
    endpoint.set_default_client_config(config);

    Ok(endpoint)
}

/// Whether to bind an IPv6 socket for outgoing connections.
///
/// A dual-stack socket would be preferable, but it is not portable enough to
/// rely on, and a LAN KVM is overwhelmingly IPv4. IPv6 is opt-in through the
/// environment until discovery lands and can answer the question properly.
fn address_hint() -> Option<String> {
    std::env::var("WRAITH_BIND_IPV6").ok()
}

fn address_is_ipv6(hint: Option<String>) -> bool {
    hint.is_some_and(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_port_is_not_deskflows() {
        // Sharing 24800 would mean two incompatible protocols answering the
        // same door, and a confusing failure for anyone running both.
        assert_ne!(DEFAULT_PORT, 24800);
    }

    #[test]
    fn the_keepalive_beats_the_receiver_watchdog() {
        // The watchdog is the backstop that works with the sender already dead.
        // The keepalive should usually get there first, so a clean disconnect
        // reads as a disconnect rather than as a timeout.
        let watchdog_ms = crate::domain::LedgerConfig::default().idle_release_ms;

        assert!(
            IDLE_TIMEOUT_MS < watchdog_ms,
            "the connection should be declared dead ({IDLE_TIMEOUT_MS}ms) before the \
             watchdog fires ({watchdog_ms}ms)"
        );
        const {
            assert!(
                KEEPALIVE_MS * 2 < IDLE_TIMEOUT_MS,
                "at least two probes before giving up"
            );
        }
    }

    #[tokio::test]
    async fn a_server_endpoint_binds_and_reports_its_address() {
        let identity = Identity::generate();
        let endpoint = server(
            &identity,
            TrustedPeers::of([identity.peer_id()]),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();

        assert_ne!(
            endpoint.local_addr().unwrap().port(),
            0,
            "the OS assigned no port"
        );
    }

    #[tokio::test]
    async fn a_client_endpoint_binds() {
        let identity = Identity::generate();
        assert!(client(&identity, TrustedPeers::new()).is_ok());
    }

    #[tokio::test]
    async fn an_empty_trust_set_still_produces_a_working_endpoint() {
        // It will refuse everyone, which is correct for a machine that has not
        // paired yet. Failing to construct would make the error appear at the
        // wrong moment, long before anyone tried to connect.
        let identity = Identity::generate();

        assert!(
            server(
                &identity,
                TrustedPeers::new(),
                "127.0.0.1:0".parse().unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn the_ipv6_hint_reads_as_a_flag_rather_than_a_string() {
        assert!(!address_is_ipv6(None));
        assert!(!address_is_ipv6(Some("0".to_owned())));
        assert!(!address_is_ipv6(Some("false".to_owned())));
        assert!(address_is_ipv6(Some("1".to_owned())));
        assert!(address_is_ipv6(Some("yes".to_owned())));
    }
}
