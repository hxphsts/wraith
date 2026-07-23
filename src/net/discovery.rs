//! Finding paired machines on the LAN.
//!
//! # Why discovery is safe here
//!
//! Discovery announces an address, not a permission. A machine that finds
//! Wraith on the network still has to present a paired identity key to connect,
//! so being discoverable grants nothing.
//!
//! That is worth stating because it is the usual objection to zero-configuration
//! networking, and it does not apply when authentication is independent of
//! addressing. The identity key is never published: only the port and the short
//! form of the key, which is enough to match a peer already in the trust store
//! and useless to anyone else.
//!
//! # What it replaces
//!
//! Typing an IP address into a config file, and then typing it again when the
//! DHCP lease changes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::config::encode_hex;
use crate::domain::PeerId;

/// The service type Wraith advertises under.
const SERVICE_TYPE: &str = "_wraith._udp.local.";

/// The property carrying the short form of the identity key.
const KEY_PROPERTY: &str = "id";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    #[error("cannot start mDNS: {0}")]
    Start(String),

    #[error("cannot advertise: {0}")]
    Advertise(String),

    #[error("cannot browse: {0}")]
    Browse(String),
}

/// A machine found on the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The short identity, for matching against the trust store.
    pub short_key: String,
    pub address: SocketAddr,
    pub name: String,
}

/// Announces this machine and watches for others.
pub struct Discovery {
    daemon: ServiceDaemon,
    /// Kept so the advertisement can be withdrawn on shutdown.
    service_name: String,
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("service", &self.service_name)
            .finish_non_exhaustive()
    }
}

impl Discovery {
    /// Starts advertising this machine.
    pub fn advertise(peer: PeerId, name: &str, port: u16) -> Result<Self, DiscoveryError> {
        let daemon =
            ServiceDaemon::new().map_err(|error| DiscoveryError::Start(error.to_string()))?;

        // The instance name is the short key rather than the hostname, because
        // two machines can share a hostname and no two share a key.
        let short = short_key(peer);
        let instance = format!("wraith-{short}");

        let mut properties = HashMap::new();
        properties.insert(KEY_PROPERTY.to_owned(), short.clone());
        properties.insert("name".to_owned(), name.to_owned());

        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            properties,
        )
        .map_err(|error| DiscoveryError::Advertise(error.to_string()))?
        .enable_addr_auto();

        let service_name = service.get_fullname().to_owned();
        daemon
            .register(service)
            .map_err(|error| DiscoveryError::Advertise(error.to_string()))?;

        tracing::info!(%short, port, "announcing this machine on the LAN");

        Ok(Self {
            daemon,
            service_name,
        })
    }

    /// Watches for other machines, calling `on_found` for each.
    ///
    /// Runs on its own thread. `mdns-sd` brings its own, and it talks over plain
    /// channels rather than a runtime, so this composes with tokio without
    /// dragging in a second reactor.
    pub fn browse<F>(&self, mut on_found: F) -> Result<(), DiscoveryError>
    where
        F: FnMut(Found) + Send + 'static,
    {
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|error| DiscoveryError::Browse(error.to_string()))?;

        std::thread::Builder::new()
            .name("wraith-discovery".to_owned())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    if let ServiceEvent::ServiceResolved(info) = event
                        && let Some(found) = resolve(&info)
                    {
                        on_found(found);
                    }
                }
            })
            .map_err(|error| DiscoveryError::Browse(error.to_string()))?;

        Ok(())
    }

    /// Withdraws the advertisement.
    ///
    /// Best effort. A machine that vanishes without unregistering ages out of
    /// other machines' caches anyway, so this only makes that faster.
    pub fn withdraw(&self) {
        let _ = self.daemon.unregister(&self.service_name);
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.withdraw();
    }
}

/// A resolved service as a peer, if it looks like one of ours.
fn resolve(service: &ResolvedService) -> Option<Found> {
    let short_key = service.get_property_val_str(KEY_PROPERTY)?.to_owned();
    let name = service
        .get_property_val_str("name")
        .unwrap_or("unknown")
        .to_owned();

    let address = best_address(
        service
            .get_addresses()
            .iter()
            .map(mdns_sd::ScopedIp::to_ip_addr),
    )?;

    Some(Found {
        short_key,
        address: SocketAddr::new(address, service.get_port()),
        name,
    })
}

/// The most dialable of a machine's addresses.
///
/// A machine on a LAN typically announces several, and taking the first is
/// wrong often enough to matter. Link-local IPv6 in particular is the usual
/// first answer and cannot be dialled at all without a scope identifier, so a
/// naive pick produces a peer that is found and then never reachable.
fn best_address(addresses: impl Iterator<Item = IpAddr>) -> Option<IpAddr> {
    addresses.max_by_key(|address| reachability(*address))
}

/// How likely an address is to work, higher being better.
///
/// Public because a caller accumulating addresses across several resolutions
/// needs the same ordering to decide whether a new one is an improvement.
#[must_use]
pub const fn reachability(address: IpAddr) -> u8 {
    match address {
        // What a machine on a home or office network actually has.
        IpAddr::V4(v4) if v4.is_private() => 4,
        // A routable v4, which is unusual on a LAN but perfectly dialable.
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() => 3,
        // Only useful when both machines are the same one, which is how the
        // tests run and occasionally how a user tries it first.
        IpAddr::V4(v4) if v4.is_loopback() => 2,
        // Routable v6. Works, but a LAN KVM rarely needs it.
        IpAddr::V6(v6) if !v6.is_loopback() && !is_link_local_v6(v6) => 1,
        // Link-local v6 needs a scope identifier we do not carry, and v4
        // link-local means DHCP failed. Last resort, and usually unusable.
        _ => 0,
    }
}

/// Whether an IPv6 address is in `fe80::/10`.
///
/// `Ipv6Addr::is_unicast_link_local` is still unstable, so this is the same
/// check written out.
const fn is_link_local_v6(address: std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

/// The first sixteen hex characters of an identity.
///
/// Enough to match against a trust store without publishing the key. Not a
/// trust decision: the connection still has to authenticate against the full
/// key, so a collision here costs a wasted dial and nothing more.
#[must_use]
pub fn short_key(peer: PeerId) -> String {
    encode_hex(&peer.0)[..16].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a valid address")
    }

    #[test]
    fn a_private_v4_address_wins() {
        // What a machine on a home or office network actually has.
        let chosen = best_address([ip("fe80::1"), ip("192.168.1.9"), ip("127.0.0.1")].into_iter());

        assert_eq!(chosen, Some(ip("192.168.1.9")));
    }

    #[test]
    fn a_link_local_v6_address_loses_to_everything() {
        // The bug this ordering exists for. Link-local v6 is often announced
        // first and cannot be dialled without a scope identifier, so taking it
        // produces a peer that is found and then never reachable.
        for better in ["10.0.0.5", "127.0.0.1", "2001:db8::1"] {
            let chosen = best_address([ip("fe80::abcd"), ip(better)].into_iter());
            assert_eq!(chosen, Some(ip(better)), "fe80:: beat {better}");
        }
    }

    #[test]
    fn loopback_is_used_when_it_is_all_there_is() {
        // How the tests run, and how a user often tries it first.
        assert_eq!(
            best_address([ip("127.0.0.1")].into_iter()),
            Some(ip("127.0.0.1"))
        );
    }

    #[test]
    fn a_link_local_address_is_better_than_nothing() {
        assert_eq!(
            best_address([ip("fe80::1")].into_iter()),
            Some(ip("fe80::1"))
        );
    }

    #[test]
    fn a_machine_announcing_nothing_is_not_reachable() {
        assert_eq!(best_address(std::iter::empty()), None);
    }

    #[test]
    fn the_fe80_prefix_is_matched_across_its_whole_range() {
        // fe80::/10 covers fe80 through febf, and checking only fe80 would let
        // most of the range through.
        for segment in [0xfe80_u16, 0xfe90, 0xfea0, 0xfebf] {
            let address = std::net::Ipv6Addr::new(segment, 0, 0, 0, 0, 0, 0, 1);
            assert!(is_link_local_v6(address), "{address} was not recognised");
        }
        assert!(!is_link_local_v6(std::net::Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_link_local_v6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn a_short_key_is_sixteen_characters() {
        assert_eq!(short_key(PeerId([0xab; 32])).len(), 16);
    }

    #[test]
    fn a_short_key_is_a_prefix_of_the_full_one() {
        // It has to be, or matching a discovered machine against the trust
        // store would silently never work.
        let peer = PeerId([0x12; 32]);

        assert!(encode_hex(&peer.0).starts_with(&short_key(peer)));
    }

    #[test]
    fn different_identities_have_different_short_keys() {
        assert_ne!(short_key(PeerId([1; 32])), short_key(PeerId([2; 32])));
    }

    #[test]
    fn the_short_key_does_not_reveal_the_whole_identity() {
        // Publishing the full key would let anyone on the network enumerate
        // exactly which machines are paired with which.
        let peer = PeerId([0x7f; 32]);

        assert!(short_key(peer).len() < encode_hex(&peer.0).len());
    }

    #[test]
    fn the_service_type_is_scoped_to_wraith() {
        // A generic type would collide with other tools and produce peers that
        // fail to authenticate for confusing reasons.
        assert!(SERVICE_TYPE.starts_with("_wraith."));
        assert!(SERVICE_TYPE.ends_with(".local."));
    }

    #[test]
    #[ignore = "needs a network interface and a working mDNS responder"]
    fn a_machine_can_advertise_itself() {
        let discovery =
            Discovery::advertise(PeerId([3; 32]), "test", 24810).expect("could not advertise");

        discovery.withdraw();
    }
}
