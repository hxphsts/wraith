//! A machine's long-term identity.
//!
//! # The identity is the key
//!
//! A peer has no name, no serial, and nothing in a registry. It is an Ed25519
//! public key, and it proves it is that peer by completing a TLS handshake with
//! the matching private key. There is nothing else to spoof.
//!
//! # The certificate's key is the identity key
//!
//! Wraith mints a self-signed certificate whose subject public key **is** the
//! identity key, and the verifier pins those SPKI bytes. The alternative, a
//! custom X.509 extension carrying the identity separately, would mean writing
//! an ASN.1 parser that runs before authentication on attacker-controlled input.
//! That is precisely the shape of every CVE in this software category. See
//! `research/03-transport-security.md`.
//!
//! So the whole verifier is a constant-time comparison of two byte strings, and
//! there is no parser to get wrong.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use zeroize::Zeroizing;

use crate::domain::PeerId;

/// Owner-only permissions for the private key file.
#[cfg(unix)]
const KEY_FILE_MODE: u32 = 0o600;

/// What can go wrong loading or minting an identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("cannot read the identity at {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot write the identity to {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("the identity at {path} is not a valid key: {reason}")]
    Malformed { path: PathBuf, reason: String },

    #[error("cannot mint a certificate: {0}")]
    Certificate(String),
}

/// This machine's keypair.
///
/// Deliberately not `Clone`. A private key that can be duplicated casually ends
/// up duplicated casually.
pub struct Identity {
    signing: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The public half only. A derived Debug would print the private key,
        // which is how a key reaches a log file.
        f.debug_struct("Identity")
            .field("peer", &self.peer_id())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generates a new identity.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rng()),
        }
    }

    /// The public half, which is how other machines refer to this one.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.signing.verifying_key().to_bytes())
    }

    /// Loads the identity at `path`, generating and saving one if absent.
    ///
    /// The generate-on-absence behaviour is deliberate. An identity is not a
    /// secret the user chose, it is a machine fact, and making them run a
    /// separate command to create one adds a step that can only be got wrong.
    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        match fs::read_to_string(path) {
            Ok(pem) => Self::from_pem(&pem, path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                identity.save(path)?;

                tracing::info!(peer = %identity.peer_id(), "generated a new identity");
                Ok(identity)
            }
            Err(source) => Err(IdentityError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    fn from_pem(pem: &str, path: &Path) -> Result<Self, IdentityError> {
        let signing =
            SigningKey::from_pkcs8_pem(pem).map_err(|error| IdentityError::Malformed {
                path: path.to_owned(),
                reason: error.to_string(),
            })?;

        Ok(Self { signing })
    }

    /// Writes the identity, never leaving it readable by anyone else.
    ///
    /// The mode is set as the file is created rather than afterwards. Creating
    /// it at the default and tightening it a moment later leaves this machine's
    /// private key world-readable in between, and a local account that opens it
    /// in that window keeps the descriptor across the change.
    ///
    /// Written beside the destination and renamed over it, because a crash
    /// partway through a direct write leaves a truncated key, and an identity
    /// that will not parse locks this machine out of every pairing it has.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| IdentityError::Write {
                path: parent.to_owned(),
                source,
            })?;
            restrict_directory(parent);
        }

        let pem = self
            .signing
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|error| IdentityError::Certificate(error.to_string()))?;

        let staging = staging_path(path);
        let write_failed = |source| IdentityError::Write {
            path: staging.clone(),
            source,
        };

        // Left behind by an interrupted save. Removing it is safe against the
        // attack this function exists to prevent, since `create_new` refuses an
        // existing path rather than following it.
        let _ = fs::remove_file(&staging);

        {
            use std::io::Write as _;

            let mut file = create_private(&staging).map_err(write_failed)?;
            file.write_all(pem.as_bytes()).map_err(write_failed)?;
            file.sync_all().map_err(write_failed)?;
        }

        fs::rename(&staging, path).map_err(|source| IdentityError::Write {
            path: path.to_owned(),
            source,
        })?;

        // Windows takes its permissions from the directory ACL rather than from
        // the open above, so it still needs a second step.
        restrict_permissions(path)?;
        Ok(())
    }

    /// A self-signed certificate whose subject public key is the identity key.
    ///
    /// The subject name is arbitrary and never checked, because the verifier
    /// pins the key rather than validating a name. It is set to the peer's short
    /// id purely so a packet capture is readable.
    pub fn certificate(&self) -> Result<Credentials, IdentityError> {
        let key_pem = self
            .signing
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map_err(|error| IdentityError::Certificate(error.to_string()))?;

        let key_pair = rcgen::KeyPair::from_pem(&key_pem)
            .map_err(|error| IdentityError::Certificate(error.to_string()))?;

        let mut params = rcgen::CertificateParams::new(vec![self.peer_id().short()])
            .map_err(|error| IdentityError::Certificate(error.to_string()))?;
        params.distinguished_name = rcgen::DistinguishedName::new();

        let certificate = params
            .self_signed(&key_pair)
            .map_err(|error| IdentityError::Certificate(error.to_string()))?;

        Ok(Credentials {
            certificate_der: certificate.der().to_vec(),
            key_der: Zeroizing::new(key_pair.serialize_der()),
        })
    }
}

/// A certificate and its private key, in the form rustls wants.
#[derive(Clone)]
pub struct Credentials {
    pub certificate_der: Vec<u8>,

    /// Wiped when this goes out of scope, including every clone.
    ///
    /// Partial cover, and worth saying so. An endpoint hands its own copy to
    /// rustls, whose `PrivateKeyDer` can be zeroized but is not on drop, so one
    /// copy outlives this and there is nothing here that can reach it. What
    /// this does remove is the rest: a fresh clone is made for every endpoint
    /// built, and without this each one left the identity key in freed heap.
    pub key_der: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private key is deliberately absent. A Debug impl that prints one
        // is how a key reaches a log file.
        f.debug_struct("Credentials")
            .field("certificate_bytes", &self.certificate_der.len())
            .finish_non_exhaustive()
    }
}

/// The default identity path, under the user's config directory.
#[must_use]
pub fn default_path() -> PathBuf {
    config_dir().join("identity.pem")
}

/// Wraith's configuration directory.
#[must_use]
pub fn config_dir() -> PathBuf {
    dir_from_env(
        std::env::var_os("WRAITH_CONFIG_DIR"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The directory resolution, split from the environment lookup so a test can
/// exercise the override without setting a process-wide variable that races
/// every other test under one `cargo test`.
fn dir_from_env(
    explicit: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    explicit.map_or_else(
        || {
            xdg.map(PathBuf::from)
                .or_else(|| home.map(|home| PathBuf::from(home).join(".config")))
                .unwrap_or_else(|| PathBuf::from("."))
                .join("wraith")
        },
        PathBuf::from,
    )
}

/// Where a save stages the key before renaming it into place.
///
/// A sibling, so the rename is within one filesystem and therefore atomic.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("identity"))
        .to_owned();
    name.push(".new");
    path.with_file_name(name)
}

/// Creates a file only this user can read, refusing one that already exists.
///
/// `create_new` is what makes this safe rather than the mode alone: it refuses
/// an existing path instead of following it, so a symlink planted at the
/// staging path cannot redirect the write.
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Keeps other accounts out of the directory holding the key.
///
/// Best effort, and deliberately so: the directory may predate Wraith or be
/// owned by something else entirely, and the key's own mode is what actually
/// protects it. This narrows who can watch the directory, nothing more.
#[cfg(unix)]
fn restrict_directory(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
        tracing::debug!(?path, %error, "cannot restrict the config directory");
    }
}

#[cfg(not(unix))]
const fn restrict_directory(_path: &Path) {}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(KEY_FILE_MODE)).map_err(|source| {
        IdentityError::Write {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(not(unix))]
const fn restrict_permissions(_path: &Path) -> Result<(), IdentityError> {
    // Windows inherits the directory ACL, and getting that right needs the
    // platform crate. Tracked for the Windows milestone.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "wraith-identity-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn a_generated_identity_has_a_stable_peer_id() {
        let identity = Identity::generate();

        assert_eq!(identity.peer_id(), identity.peer_id());
    }

    #[test]
    fn two_identities_differ() {
        assert_ne!(
            Identity::generate().peer_id(),
            Identity::generate().peer_id()
        );
    }

    #[test]
    fn an_identity_survives_a_round_trip_through_disk() {
        // The peer id is what other machines have stored, so a load that
        // produced a different one would silently break every pairing.
        let dir = temp_dir();
        let path = dir.join("identity.pem");

        let original = Identity::generate();
        original.save(&path).unwrap();
        let loaded = Identity::load_or_generate(&path).unwrap();

        assert_eq!(original.peer_id(), loaded.peer_id());
    }

    #[test]
    fn loading_an_absent_identity_generates_and_persists_one() {
        let dir = temp_dir();
        let path = dir.join("nested").join("identity.pem");

        let first = Identity::load_or_generate(&path).unwrap();
        let second = Identity::load_or_generate(&path).unwrap();

        assert!(path.exists(), "the generated identity was not saved");
        assert_eq!(
            first.peer_id(),
            second.peer_id(),
            "a second load regenerated the key"
        );
    }

    #[test]
    fn a_malformed_identity_is_an_error_rather_than_a_fresh_key() {
        // Silently replacing an unreadable key would break every existing
        // pairing while looking like success, which is the worst outcome.
        let dir = temp_dir();
        let path = dir.join("identity.pem");
        fs::write(&path, "this is not a key").unwrap();

        let error = Identity::load_or_generate(&path).expect_err("a malformed key must fail");

        assert!(
            matches!(error, IdentityError::Malformed { .. }),
            "got {error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_identity_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir();
        let path = dir.join("identity.pem");
        Identity::generate().save(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(
            mode, KEY_FILE_MODE,
            "the private key is group or world readable"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_where_the_key_is_staged_is_refused_rather_than_followed() {
        // The reason the write is staged and the mode set at creation. A local
        // account that can guess the path plants a link to something it wants
        // destroyed, and an open that creates-and-truncates empties it.
        let dir = temp_dir();
        let path = dir.join("identity.pem");
        let victim = dir.join("precious");
        fs::write(&victim, b"do not lose this").unwrap();

        std::os::unix::fs::symlink(&victim, staging_path(&path)).unwrap();

        let original = Identity::generate();
        original.save(&path).unwrap();

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do not lose this",
            "the write followed a planted symlink"
        );
        assert_eq!(
            Identity::load_or_generate(&path).unwrap().peer_id(),
            original.peer_id(),
            "and the identity still landed where it belongs"
        );
    }

    #[test]
    #[cfg(unix)]
    fn replacing_an_identity_leaves_it_owner_only() {
        // The rename lands on a path that already exists, and the mode has to
        // come from the staged file rather than from whatever was there before.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir();
        let path = dir.join("identity.pem");

        fs::write(&path, b"stale").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let identity = Identity::generate();
        identity.save(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE, "a replaced key is still owner-only");
        assert_eq!(
            Identity::load_or_generate(&path).unwrap().peer_id(),
            identity.peer_id()
        );
    }

    #[test]
    fn a_certificate_carries_the_identity_key_as_its_subject_key() {
        // The whole verifier rests on this. If the certificate's key were a
        // fresh one rather than the identity, pinning the SPKI would pin
        // something unrelated and authenticate nothing.
        let identity = Identity::generate();
        let credentials = identity.certificate().unwrap();

        let spki = super::super::verify::subject_public_key(&credentials.certificate_der)
            .expect("the certificate should parse");

        assert_eq!(
            spki,
            identity.peer_id().0,
            "the certificate does not carry the identity key"
        );
    }

    #[test]
    fn credentials_do_not_print_the_private_key() {
        let credentials = Identity::generate().certificate().unwrap();

        let rendered = format!("{credentials:?}");

        assert!(
            !rendered.contains("key_der"),
            "Debug exposed the private key"
        );
    }

    #[test]
    fn the_config_directory_honours_an_explicit_override() {
        // The override is what makes the integration tests able to run without
        // touching the developer's own identity.
        assert_eq!(
            dir_from_env(Some("/tmp/wraith-test-config".into()), None, None),
            PathBuf::from("/tmp/wraith-test-config"),
        );
    }
}
