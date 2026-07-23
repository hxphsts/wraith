//! Certificate verification, pinned to known identity keys.
//!
//! # Why there is almost nothing here
//!
//! Every published vulnerability in this software category came through one of
//! two doors: memory safety in a parser handling attacker-controlled network
//! data, or a missing authentication step. See
//! `research/03-transport-security.md`.
//!
//! This module is where both doors would be. So it does the least possible: it
//! finds the subject public key in the certificate, compares it in constant time
//! against a set of keys the user has explicitly paired with, and accepts or
//! refuses. No name validation, no certificate authority, no chain building, no
//! expiry, no revocation.
//!
//! There is no trust-on-first-use branch. An unpaired peer is refused before it
//! can send a byte of input, which makes CVE-2021-42072 and CVE-2021-42073
//! unrepresentable rather than fixed.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::domain::PeerId;

/// The Ed25519 subject public key of a DER certificate.
///
/// A deliberately minimal scan rather than a general X.509 parser. An Ed25519
/// `SubjectPublicKeyInfo` ends with a fixed 12-byte prefix followed by the 32
/// key bytes, and in a certificate carrying one Ed25519 key that prefix appears
/// exactly once.
///
/// Writing a full ASN.1 parser here would put exactly the code that produced
/// this category's CVE history on the pre-authentication path. Refusing to have
/// one is the point.
///
/// The uniqueness is checked rather than assumed. This runs before
/// authentication on bytes a stranger chose, and a scan that simply takes the
/// first match is a scan they can aim: put the prefix in an extension ahead of
/// the real key and the answer comes from there instead. Nothing downstream is
/// fooled, since the result still has to equal a pinned key and the handshake
/// independently proves possession, but "there is no parser to get wrong" is
/// only true while there is nothing to steer either.
#[must_use]
pub fn subject_public_key(certificate_der: &[u8]) -> Option<[u8; 32]> {
    // SEQUENCE(30 12) { SEQUENCE(30 05) { OID(06 03 2b 65 70) } BIT STRING(03 21 00) }
    // The OID 1.3.101.112 is Ed25519.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let mut matches = certificate_der
        .windows(ED25519_SPKI_PREFIX.len())
        .enumerate()
        .filter(|&(_, window)| window == ED25519_SPKI_PREFIX)
        .map(|(at, _)| at);

    let start = matches.next()? + ED25519_SPKI_PREFIX.len();

    // Refused rather than resolved. A certificate carrying the prefix twice was
    // built to make this choose, and there is no reading of it worth guessing.
    if matches.next().is_some() {
        return None;
    }

    certificate_der.get(start..start + 32)?.try_into().ok()
}

/// Whether two keys match, without leaking where they first differ.
///
/// Timing here is not obviously exploitable, since the attacker is comparing
/// against a public key they could simply ask for. Doing it in constant time
/// anyway costs nothing and removes the need to have that argument.
fn keys_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// The peers this machine has paired with.
///
/// **A live handle, not a snapshot, and `Clone` shares rather than copies.**
/// A rustls `ServerConfig` takes its verifier once and cannot be given another,
/// so the set the verifier consults has to be the thing that changes. Cloning
/// this into both endpoints and then adding a peer means the next handshake
/// accepts it, with no endpoint rebuilt and no restart.
///
/// Copying instead is what made a machine paired while a session was running
/// unable to connect until the session was restarted: the verifier went on
/// consulting the set as it stood when the socket was bound.
#[derive(Debug, Clone, Default)]
pub struct TrustedPeers {
    peers: Arc<RwLock<BTreeSet<PeerId>>>,
}

impl TrustedPeers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn of(peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            peers: Arc::new(RwLock::new(peers.into_iter().collect())),
        }
    }

    /// Trusts one more machine, from now on, everywhere this handle was cloned.
    pub fn insert(&self, peer: PeerId) -> bool {
        self.peers.write().is_ok_and(|mut peers| peers.insert(peer))
    }

    /// Trusts exactly these, for a trust store re-read from disk.
    ///
    /// Reports whether it took. A poisoned lock leaves the old set in place,
    /// and the old set is the one that still trusts a machine the user has just
    /// asked to forget, so a caller that ignores this is quietly not revoking
    /// anything. `identify` fails closed on the same lock; this cannot, because
    /// refusing everyone is not a safe reading of "the reload did not happen".
    #[must_use]
    pub fn replace(&self, peers: impl IntoIterator<Item = PeerId>) -> bool {
        let next = peers.into_iter().collect();

        self.peers.write().is_ok_and(|mut peers| {
            *peers = next;
            true
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.read().is_ok_and(|peers| peers.is_empty())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.read().map_or(0, |peers| peers.len())
    }

    /// The peer this certificate belongs to, if it is one we trust.
    ///
    /// Takes a read lock during a TLS handshake. Never held across an await,
    /// because this is sync, and `replace` builds its set before taking the
    /// write lock so a writer never holds it across any work.
    #[must_use]
    pub fn identify(&self, certificate_der: &[u8]) -> Option<PeerId> {
        let presented = subject_public_key(certificate_der)?;
        let Ok(peers) = self.peers.read() else {
            return None;
        };

        // Every trusted key is compared, rather than returning on the first
        // match, so the work does not depend on which peer connected.
        let mut found = None;
        for peer in peers.iter() {
            if keys_match(&peer.0, &presented) {
                found = Some(*peer);
            }
        }
        found
    }
}

/// What went wrong verifying a peer.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the peer presented a certificate with no Ed25519 key")]
    NoKey,

    #[error("the peer {0} is not paired with this machine")]
    NotPaired(PeerId),
}

/// Verifies a peer against the pinned set, in both directions.
///
/// One type implements both rustls verifier traits because the check is
/// identical: a Wraith peer is a Wraith peer, and which side dialled is a
/// networking detail rather than a trust one.
#[derive(Debug)]
pub struct PinnedVerifier {
    trusted: TrustedPeers,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedVerifier {
    #[must_use]
    pub fn new(trusted: TrustedPeers) -> Self {
        Self {
            trusted,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Checks a certificate, returning the peer it belongs to.
    fn check(&self, certificate: &CertificateDer<'_>) -> Result<PeerId, rustls::Error> {
        let presented = subject_public_key(certificate)
            .ok_or_else(|| rustls::Error::General(VerifyError::NoKey.to_string()))?;

        self.trusted.identify(certificate).ok_or_else(|| {
            // The unpaired key is named in the error so a user who has just
            // reinstalled can see which identity turned up unexpectedly.
            rustls::Error::General(VerifyError::NotPaired(PeerId(presented)).to_string())
        })
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The server name is deliberately ignored. Wraith pins keys, and a
        // machine's name or address is not part of its identity.
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

impl ClientCertVerifier for PinnedVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No hints. Wraith clients know which certificate to present because
        // they only have one.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        // The whole point. A client that presents no certificate is refused
        // rather than admitted as anonymous.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::identity::Identity;

    #[test]
    fn the_subject_key_is_found_in_a_real_certificate() {
        let identity = Identity::generate();
        let credentials = identity.certificate().unwrap();

        assert_eq!(
            subject_public_key(&credentials.certificate_der),
            Some(identity.peer_id().0)
        );
    }

    #[test]
    fn a_certificate_carrying_two_candidate_keys_is_refused() {
        // A stranger chooses these bytes, and they reach this scan before
        // anything has authenticated. Planting the prefix a second time is the
        // one way to steer a first-match scan, so a second occurrence has to be
        // a refusal rather than a choice.
        let credentials = Identity::generate().certificate().unwrap();
        let real = &credentials.certificate_der;

        let planted: Vec<u8> = real.iter().copied().chain(real.iter().copied()).collect();

        assert_eq!(
            subject_public_key(&planted),
            None,
            "an ambiguous certificate yielded a key anyway"
        );
    }

    #[test]
    fn a_certificate_with_no_ed25519_key_yields_nothing() {
        assert_eq!(subject_public_key(&[0_u8; 64]), None);
        assert_eq!(subject_public_key(&[]), None);
    }

    #[test]
    fn a_truncated_certificate_does_not_panic() {
        // Attacker-controlled input arriving before authentication. Every
        // prefix of a real certificate must be refused rather than indexed.
        let credentials = Identity::generate().certificate().unwrap();

        for length in 0..credentials.certificate_der.len() {
            let _ = subject_public_key(&credentials.certificate_der[..length]);
        }
    }

    #[test]
    fn a_trusted_peer_is_identified() {
        let identity = Identity::generate();
        let credentials = identity.certificate().unwrap();
        let trusted = TrustedPeers::of([identity.peer_id()]);

        assert_eq!(
            trusted.identify(&credentials.certificate_der),
            Some(identity.peer_id())
        );
    }

    #[test]
    fn an_unpaired_peer_is_not_identified() {
        // The case that makes CVE-2021-42072 unrepresentable: a peer we have
        // never paired with is refused, not admitted under some default name.
        let stranger = Identity::generate();
        let credentials = stranger.certificate().unwrap();
        let trusted = TrustedPeers::of([Identity::generate().peer_id()]);

        assert_eq!(trusted.identify(&credentials.certificate_der), None);
    }

    #[test]
    fn a_machine_paired_after_the_verifier_was_built_is_trusted() {
        // The bug this type exists to prevent, stated. A rustls config takes
        // its verifier once, so a set that was copied into one would go on
        // answering as it stood when the socket was bound, and a machine paired
        // while a session was running could not connect until a restart.
        let identity = Identity::generate();
        let credentials = identity.certificate().unwrap();
        let presented: CertificateDer<'_> = credentials.certificate_der.into();

        let trusted = TrustedPeers::new();
        let verifier = PinnedVerifier::new(trusted.clone());

        assert!(verifier.check(&presented).is_err(), "not paired yet");

        trusted.insert(identity.peer_id());

        assert_eq!(
            verifier.check(&presented).unwrap(),
            identity.peer_id(),
            "the verifier consults the set as it stands now, not as it was built"
        );
    }

    #[test]
    fn replacing_the_trust_set_drops_what_is_no_longer_in_it() {
        // A trust store re-read from disk after a machine was forgotten. The
        // dropped peer must stop being accepted, not merely stop being listed.
        let stays = Identity::generate();
        let goes = Identity::generate();

        let trusted = TrustedPeers::of([stays.peer_id(), goes.peer_id()]);
        assert!(trusted.replace([stays.peer_id()]), "the reload must take");

        assert_eq!(trusted.len(), 1);
        assert_eq!(
            trusted.identify(&goes.certificate().unwrap().certificate_der),
            None
        );
    }

    #[test]
    fn an_empty_trust_set_accepts_nobody() {
        // There is no bootstrap path where the first peer is trusted for being
        // first. Pairing is the only way in.
        let credentials = Identity::generate().certificate().unwrap();

        assert_eq!(
            TrustedPeers::new().identify(&credentials.certificate_der),
            None
        );
    }

    #[test]
    fn key_comparison_agrees_with_equality() {
        let a = [7_u8; 32];
        let mut b = a;

        assert!(keys_match(&a, &b));

        b[31] ^= 1;
        assert!(
            !keys_match(&a, &b),
            "a difference in the last byte must be caught"
        );

        b = a;
        b[0] ^= 1;
        assert!(
            !keys_match(&a, &b),
            "a difference in the first byte must be caught"
        );
    }

    #[test]
    fn the_verifier_accepts_a_paired_peer_and_refuses_a_stranger() {
        let paired = Identity::generate();
        let stranger = Identity::generate();
        let verifier = PinnedVerifier::new(TrustedPeers::of([paired.peer_id()]));

        let good = CertificateDer::from(paired.certificate().unwrap().certificate_der);
        let bad = CertificateDer::from(stranger.certificate().unwrap().certificate_der);

        assert_eq!(verifier.check(&good).unwrap(), paired.peer_id());
        assert!(verifier.check(&bad).is_err());
    }

    #[test]
    fn client_authentication_is_mandatory() {
        // If this ever returns false, an anonymous peer can connect and the
        // whole trust model is gone.
        let verifier = PinnedVerifier::new(TrustedPeers::new());

        assert!(ClientCertVerifier::client_auth_mandatory(&verifier));
    }
}
