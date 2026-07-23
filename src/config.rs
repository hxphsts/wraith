//! Configuration and the trust store.
//!
//! Two files. `config.toml` describes the desk, `peers.toml` records who this
//! machine has paired with, and **neither is meant to be edited by hand**.
//!
//! Pairing writes both. The window rewrites the desk when you drag a screen. A
//! peer that rearranges its own desk pushes the change here. They are readable
//! TOML because an opaque blob in a config directory is worse to debug, not
//! because opening one is the intended path.
//!
//! Deskflow's fifth-worst complaint is users hand-editing a trust file, and an
//! earlier version of Wraith reproduced it exactly: a desk had to be written
//! twice, mirrored, on two machines, with nothing checking the halves agreed.
//! The desk is a grid now, so adjacency is the link and there is one statement
//! of each fact rather than two. See `crate::domain::grid`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::{Cell, Edge, Grid, PeerId};
use crate::net::identity::config_dir;
use crate::net::verify::TrustedPeers;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{path} is not valid TOML: {reason}")]
    Malformed { path: PathBuf, reason: String },

    #[error("screen {0} is listed twice")]
    DuplicateScreen(String),

    #[error("{first} and {second} are both at column {}, row {}", .at.column, .at.row)]
    SharedCell {
        first: String,
        second: String,
        at: Cell,
    },

    #[error("no screen is named {0}, which is what this machine calls itself")]
    NoLocalScreen(String),

    #[error("{0}")]
    UnusableName(String),
}

/// One paired machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// What the user calls it. Cosmetic, and safe to change.
    pub name: String,
    /// The identity key, hex encoded. This is what actually matters.
    pub key: String,
    /// Where to reach it, if it is not discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl Peer {
    /// The peer id, if the stored key is well formed.
    #[must_use]
    pub fn peer_id(&self) -> Option<PeerId> {
        let bytes = decode_hex(&self.key)?;
        Some(PeerId(bytes))
    }
}

/// Everything this machine has paired with.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Peers {
    #[serde(default)]
    pub peer: Vec<Peer>,
}

impl Peers {
    #[must_use]
    pub fn path() -> PathBuf {
        config_dir().join("peers.toml")
    }

    /// Loads the trust store, treating absence as empty.
    ///
    /// Absence is the state of a machine that has not paired yet, which is
    /// normal rather than an error.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|error| ConfigError::Malformed {
                path: path.to_owned(),
                reason: error.to_string(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: parent.to_owned(),
                source,
            })?;
        }

        let text = toml::to_string(self).map_err(|error| ConfigError::Malformed {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;

        fs::write(path, text).map_err(|source| ConfigError::Write {
            path: path.to_owned(),
            source,
        })
    }

    /// Adds or updates a peer, keyed by identity rather than by name.
    ///
    /// Re-pairing an existing machine updates its name and address in place. A
    /// second entry with the same key would be a second identity to trust for
    /// no reason, and a renamed machine is still the same machine.
    pub fn upsert(&mut self, peer: Peer) {
        if let Some(existing) = self.peer.iter_mut().find(|p| p.key == peer.key) {
            *existing = peer;
            return;
        }
        self.peer.push(peer);
    }

    /// Removes a peer by name, returning whether anything was removed.
    pub fn remove_named(&mut self, name: &str) -> bool {
        let before = self.peer.len();
        self.peer.retain(|peer| peer.name != name);
        before != self.peer.len()
    }

    /// The trust set, skipping any entry whose key does not parse.
    ///
    /// A malformed key is dropped with a warning rather than failing the load.
    /// Refusing to start because one line of the trust file is corrupt would
    /// take out every working pairing alongside the broken one.
    #[must_use]
    pub fn trusted(&self) -> TrustedPeers {
        let trusted = TrustedPeers::new();

        for peer in &self.peer {
            if let Some(id) = peer.peer_id() {
                trusted.insert(id);
            } else {
                tracing::warn!(
                    name = %peer.name,
                    "ignoring a peer whose key is not 64 hex characters"
                );
            }
        }
        trusted
    }

    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Peer> {
        self.peer.iter().find(|peer| peer.name == name)
    }
}

/// What putting this machine back on its own desk had to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Repair {
    /// The desk already named this machine, and the name was already written.
    None,
    /// The desk was right, and what this machine calls itself is now recorded.
    Anchored,
    /// The keyless screen was this machine under an older name.
    Renamed { from: String },
    /// No screen belonged to this machine, so one was added.
    Added { at: Cell },
}

impl Repair {
    /// Whether the desk on disk is now out of date.
    #[must_use]
    pub const fn changed(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One screen on the desk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenConfig {
    pub name: String,

    /// Where it sits. Adjacent screens are linked; there are no edges to declare.
    pub at: Cell,

    /// The peer's identity, so a rename cannot break the desk.
    ///
    /// Optional because the local machine has no peer entry to point at, and
    /// because a desk written before a peer was known is still usable by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl ScreenConfig {
    #[must_use]
    pub fn new(name: impl Into<String>, at: Cell) -> Self {
        Self {
            name: name.into(),
            at,
            key: None,
        }
    }

    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }
}

/// What a crossing looks like, if anything.
///
/// Named for what it draws rather than how much of it there is, because the two
/// are not a scale: one is a bundle of threads reaching back from the edge and
/// the other is a bar of light on it, and neither is a smaller version of the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Wisp {
    /// Seven threads fanned along the edge, reaching in and fading.
    #[default]
    Tendrils,

    /// One soft bar of light against the edge.
    Pulse,

    /// Nothing at all.
    Off,
}

impl Wisp {
    /// What to write in the config file, and what the window shows on a button.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tendrils => "tendrils",
            Self::Pulse => "pulse",
            Self::Off => "off",
        }
    }

    /// Every choice, in the order they belong on screen.
    #[must_use]
    pub const fn every() -> [Self; 3] {
        [Self::Tendrils, Self::Pulse, Self::Off]
    }
}

/// The desk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// What this machine calls itself, matching one of the screen names.
    #[serde(default)]
    pub name: Option<String>,

    /// The address to listen on. Defaults to every interface on the Wraith port.
    #[serde(default)]
    pub listen: Option<String>,

    #[serde(default)]
    pub screen: Vec<ScreenConfig>,

    /// What a crossing draws on this machine.
    ///
    /// Local rather than shared with the desk, because it is about this screen
    /// and the person looking at it, not about how the machines are arranged.
    #[serde(default)]
    pub wisp: Wisp,
}

impl Config {
    #[must_use]
    pub fn path() -> PathBuf {
        config_dir().join("config.toml")
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|error| ConfigError::Malformed {
                path: path.to_owned(),
                reason: explain(&text, &error.to_string()),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// This machine's name, falling back to the hostname.
    #[must_use]
    pub fn local_name(&self) -> String {
        self.name.clone().unwrap_or_else(hostname)
    }

    /// Writes the desk.
    ///
    /// The counterpart to `Peers::save`. Pairing and the window both write the
    /// desk, so nobody has to edit it by hand.
    ///
    /// Emitted with `to_string` rather than `to_string_pretty`, which breaks
    /// every array across four lines. A cell is two numbers and belongs on one.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: parent.to_owned(),
                source,
            })?;
        }

        let text = toml::to_string(self).map_err(|error| ConfigError::Malformed {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;

        fs::write(path, text).map_err(|source| ConfigError::Write {
            path: path.to_owned(),
            source,
        })
    }

    /// The desk as a grid.
    #[must_use]
    pub fn grid(&self) -> Grid {
        Grid::of(
            self.screen
                .iter()
                .map(|screen| (screen.name.clone(), screen.at)),
        )
    }

    /// Moves every screen to where the grid puts it.
    ///
    /// Screens the grid does not mention are dropped, and screens it adds are
    /// appended, so this is the one call the window needs after a drag.
    pub fn apply(&mut self, grid: &Grid) {
        self.screen.retain(|screen| grid.contains(&screen.name));

        for screen in &mut self.screen {
            if let Some(at) = grid.cell_of(&screen.name) {
                screen.at = at;
            }
        }

        for (name, at) in grid.iter() {
            if !self.screen.iter().any(|screen| screen.name == name) {
                self.screen.push(ScreenConfig::new(name, at));
            }
        }

        // Sorted so the file is stable across rewrites and a diff shows what
        // actually moved rather than what happened to be reordered.
        self.screen.sort_by(|a, b| a.name.cmp(&b.name));
    }

    /// Puts a screen on the desk, or moves one already there.
    ///
    /// The local machine is added at the origin if the desk is empty, because a
    /// desk with a peer and no local screen is not a desk.
    pub fn place(&mut self, name: &str, at: Cell, key: Option<&str>) -> Result<(), ConfigError> {
        let local = self.local_name();

        // Written down on the first placement and never rewritten. Deriving it
        // from the hostname on every read means a machine that starts answering
        // with its fully qualified name, or with anything else, falls off its
        // own desk and cannot start.
        self.name.get_or_insert_with(|| local.clone());

        // A machine already here under an older name is the same machine.
        // Without this, re-pairing after a rename left the desk carrying it
        // twice, under both names and with one identity key, and the second
        // copy sat wherever the first one was not.
        if let Some(key) = key
            && let Some(existing) = self
                .screen_for_key(key)
                .map(|screen| screen.name.clone())
                .filter(|existing| existing != name)
        {
            tracing::info!(%existing, %name, "a paired machine came back under a new name");
            self.screen.retain(|screen| screen.name != existing);
        }

        let mut grid = self.grid();

        if grid.is_empty() && name != local {
            grid.place(&local, Cell::ORIGIN)
                .map_err(ConfigError::from)?;
        }
        grid.place(name, at).map_err(ConfigError::from)?;

        self.apply(&grid);

        if let Some(key) = key
            && let Some(screen) = self.screen.iter_mut().find(|screen| screen.name == name)
        {
            screen.key = Some(key.to_owned());
        }

        Ok(())
    }

    /// Puts this machine back on its own desk.
    ///
    /// The local screen is the one with no `key`: pairing sets a key for every
    /// peer, and the local machine has no peer entry to point at. So a desk
    /// that names no screen after this machine, and holds exactly one keyless
    /// screen, is this machine under an older name. Renaming it in place keeps
    /// its cell, and therefore every neighbour it had.
    ///
    /// Never refuses. A desk that does not name this machine is exactly the
    /// desk somebody needs the window to repair, and the window can only reach
    /// a session that started.
    pub fn repair_local(&mut self) -> Repair {
        let local = self.local_name();

        // A machine that only receives input needs no screen of its own, and
        // inventing one would put a stranger on an empty desk.
        if self.screen.is_empty() {
            return Repair::None;
        }

        let keyless: Vec<usize> = self
            .screen
            .iter()
            .enumerate()
            .filter(|(_, screen)| screen.key.is_none())
            .map(|(index, _)| index)
            .collect();

        // Driven by the key rather than by the name. A screen merely *named*
        // after this machine may be a peer that happens to share our hostname,
        // and adopting it would hand the local screen to somebody else.
        if let [only] = keyless[..] {
            if self.screen[only].name == local {
                return self.anchor(local);
            }
            if self.screen.iter().any(|screen| screen.name == local) {
                tracing::warn!(
                    %local,
                    "a paired machine already goes by this machine's name, so the desk \
                     has been left alone. Rename one of them or forget the other"
                );
                return Repair::None;
            }

            let from = std::mem::replace(&mut self.screen[only].name, local.clone());
            self.anchor(local);
            return Repair::Renamed { from };
        }

        if self.screen.iter().any(|screen| screen.name == local) {
            return self.anchor(local);
        }

        if keyless.len() > 1 {
            // A wrong guess renames somebody else's screen, and there is no
            // signal here to choose between them. Only a hand-edited file gets
            // into this state.
            tracing::warn!(
                keyless = keyless.len(),
                "several screens carry no identity, so none can be assumed to be \
                 this machine. Adding one rather than renaming the wrong screen"
            );
        }

        let at = self.free_local_cell();
        self.screen.push(ScreenConfig::new(local.clone(), at));
        self.screen.sort_by(|a, b| a.name.cmp(&b.name));
        self.anchor(local);

        Repair::Added { at }
    }

    /// Changes what this machine calls itself, and its screen with it.
    ///
    /// **One operation, not two.** `Config::name` moving while the local
    /// screen's name did not is exactly the half-applied rename that leaves a
    /// desk failing `validate` with `NoLocalScreen`, which the session reports
    /// by refusing to start at all. The two writes must not be separable by a
    /// `?`, which is why every refusal happens before either of them.
    ///
    /// The local screen is found by the keyless rule `repair_local` uses, not
    /// by name: a screen merely named after this machine may be a peer that
    /// shares our hostname, and renaming that one hands our screen away.
    pub fn rename_local(&mut self, to: &str) -> Result<(), ConfigError> {
        let to = to.trim();
        if to.is_empty() {
            return Err(ConfigError::UnusableName(
                "a machine needs a name".to_owned(),
            ));
        }
        // The same rule the hostname goes through, so a rename cannot produce a
        // name this machine would never announce.
        if to != first_label(to) {
            return Err(ConfigError::UnusableName(format!(
                "{to} has a dot in it, and a machine is named by its first label"
            )));
        }

        let from = self.local_name();
        if from == to {
            return Ok(());
        }

        if self.screen.iter().any(|screen| screen.name == to) {
            return Err(ConfigError::DuplicateScreen(to.to_owned()));
        }

        // Refusals are done. From here nothing may fail.
        if let Some(screen) = self
            .screen
            .iter_mut()
            .find(|screen| screen.key.is_none() && screen.name == from)
        {
            to.clone_into(&mut screen.name);
        }
        self.name = Some(to.to_owned());
        self.screen.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(())
    }

    /// Writes down what this machine is called, if it is not written already.
    fn anchor(&mut self, local: String) -> Repair {
        match self.name.replace(local) {
            Some(_) => Repair::None,
            None => Repair::Anchored,
        }
    }

    /// Where a screen for this machine can go and still be reachable.
    ///
    /// `free_cell` walks outward until it finds an empty cell, so its answer
    /// always touches an occupied one. A screen the cursor cannot reach would
    /// be no repair at all.
    fn free_local_cell(&self) -> Cell {
        let grid = self.grid();

        if grid.at(Cell::ORIGIN).is_none() {
            Cell::ORIGIN
        } else {
            grid.free_cell(Cell::ORIGIN, Edge::Left)
        }
    }

    /// The screen with this name, if the desk has one.
    #[must_use]
    pub fn screen_of(&self, name: &str) -> Option<&ScreenConfig> {
        self.screen.iter().find(|screen| screen.name == name)
    }

    /// The screen belonging to an identity, whatever it is called.
    ///
    /// Preferred over the name, so renaming a machine on one side does not
    /// silently take it off the other side's desk.
    #[must_use]
    pub fn screen_for_key(&self, key: &str) -> Option<&ScreenConfig> {
        self.screen
            .iter()
            .find(|screen| screen.key.as_deref() == Some(key))
    }

    /// Checks the desk describes something possible.
    ///
    /// Two checks, down from three. "This neighbour does not exist" is gone
    /// because a grid cannot name one.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for screen in &self.screen {
            if !seen.insert(screen.name.as_str()) {
                return Err(ConfigError::DuplicateScreen(screen.name.clone()));
            }
        }

        let grid = self.grid();
        if let Some((second, at)) = grid.collisions().first() {
            let first = grid
                .iter()
                .find(|(name, cell)| *cell == *at && name != second)
                .map_or("another screen", |(name, _)| name);

            return Err(ConfigError::SharedCell {
                first: first.to_owned(),
                second: (*second).to_owned(),
                at: *at,
            });
        }

        let local = self.local_name();
        if !self.screen.is_empty() && !seen.contains(local.as_str()) {
            return Err(ConfigError::NoLocalScreen(local));
        }

        Ok(())
    }

    /// Screens that no chain of adjacency reaches from this machine.
    ///
    /// They look placed and can never receive the cursor, which is worth saying
    /// out loud rather than leaving to be discovered.
    #[must_use]
    pub fn stranded(&self) -> Vec<String> {
        let grid = self.grid();
        let reachable = grid.reachable_from(&self.local_name());

        grid.iter()
            .map(|(name, _)| name)
            .filter(|name| !reachable.contains(name))
            .map(str::to_owned)
            .collect()
    }
}

impl From<crate::domain::GridError> for ConfigError {
    fn from(error: crate::domain::GridError) -> Self {
        let crate::domain::GridError::Occupied { at, occupant } = error;

        Self::SharedCell {
            first: occupant,
            second: "the screen being placed".to_owned(),
            at,
        }
    }
}

/// A parse failure, in terms a reader can act on.
///
/// A desk written in the neighbour-by-name format that predates cells makes
/// serde say "missing field `at`", which is true and useless. The fix is to
/// pair again rather than to hand-translate it, so the error says that.
fn explain(text: &str, reason: &str) -> String {
    const OLD_KEYS: [&str; 4] = ["left =", "right =", "up =", "down ="];

    if OLD_KEYS.iter().any(|key| text.contains(key)) {
        return format!(
            "this desk is in the old neighbour format, which named the screen beside each \
             edge. Wraith stores positions now, and pairing writes them. Delete this file and \
             run `wraith pair` again on both machines ({reason})"
        );
    }
    reason.to_owned()
}

/// What this machine calls itself, as one word.
///
/// Three sources, because no one of them covers every system. `HOSTNAME` is set
/// by bash but not by zsh, and `/etc/hostname` does not exist on macOS, which
/// between them left every Mac calling itself `this-machine` and showing that
/// on both desks.
///
/// The command is the fallback rather than the first choice: it is the only one
/// that works everywhere, and the only one that costs a process.
///
/// Only the first label survives, whichever source answered. macOS gives the
/// Bonjour name and plenty of Linux boxes give the FQDN, so `ember.local` and
/// `ember.forge.computer` are both this machine, called `ember`. Trimming one
/// known suffix instead left every other domain on the desk, and a dotted name
/// there is what stopped a machine finding its own screen.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .or_else(hostname_command)
        .map(|name| first_label(name.trim()).to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this-machine".to_owned())
}

/// Everything before the first dot.
///
/// Applied to whichever source answered rather than to the command alone, since
/// `/etc/hostname` and `HOSTNAME` can both hold a fully qualified name too.
fn first_label(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

fn hostname_command() -> Option<String> {
    let output = std::process::Command::new("hostname").output().ok()?;

    String::from_utf8(output.stdout)
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// 64 hex characters as 32 bytes.
fn decode_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }

    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let pair = text.get(index * 2..index * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

/// 32 bytes as 64 hex characters.
#[must_use]
pub fn encode_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Edge;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wraith-config-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// A desktop with a laptop to its right, as this machine sees it.
    fn desk(local: &str) -> Config {
        Config {
            name: Some(local.to_owned()),
            listen: None,
            screen: vec![
                ScreenConfig::new("desktop", Cell::ORIGIN),
                ScreenConfig::new("laptop", Cell::new(1, 0)),
            ],
            ..Config::default()
        }
    }

    /// The state a Mac was found in: paired under a name the machine no longer
    /// answers to, with no `name` line to anchor it. The keyless screen is this
    /// machine; the other carries a peer's key.
    fn orphaned_desk() -> Config {
        Config {
            name: None,
            listen: None,
            screen: vec![
                ScreenConfig::new("this-machine", Cell::ORIGIN),
                ScreenConfig::new("forge", Cell::new(1, 0)).with_key("a".repeat(64)),
            ],
            ..Config::default()
        }
    }

    #[test]
    fn renaming_this_machine_moves_its_screen_and_keeps_its_cell() {
        // The name and the screen are one operation. Moving one without the
        // other is what leaves a desk the session refuses to start on.
        let mut config = orphaned_desk();
        config.repair_local();

        config.rename_local("workstation").unwrap();

        assert_eq!(config.name.as_deref(), Some("workstation"));
        assert_eq!(config.screen_of("workstation").unwrap().at, Cell::ORIGIN);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn renaming_to_a_name_already_on_the_desk_is_refused() {
        // Caught before either write, rather than by validate after the file is
        // already on disk.
        let mut config = orphaned_desk();
        config.repair_local();
        let before = config.local_name();

        assert!(config.rename_local("forge").is_err());
        assert_eq!(config.local_name(), before, "and nothing moved");
    }

    #[test]
    fn renaming_to_a_dotted_name_is_refused() {
        // The same rule the hostname goes through, so a rename cannot produce a
        // name this machine would never announce.
        let mut config = orphaned_desk();
        config.repair_local();

        assert!(config.rename_local("ember.forge.computer").is_err());
    }

    #[test]
    fn renaming_leaves_peer_keys_alone() {
        // A peer's name belongs to that peer.
        let mut config = orphaned_desk();
        config.repair_local();

        config.rename_local("workstation").unwrap();

        let peer = config.screen_of("forge").unwrap();
        assert_eq!(peer.key.as_deref(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn renaming_to_the_same_name_writes_nothing() {
        let mut config = orphaned_desk();
        config.repair_local();
        let before = config.screen.clone();

        config.rename_local(&config.local_name()).unwrap();

        assert_eq!(before.len(), config.screen.len());
    }

    #[test]
    fn a_peer_sharing_this_machines_name_is_not_adopted() {
        // Driving the repair off the name rather than the key would hand the
        // local screen to whichever peer happened to share our hostname.
        let mut config = Config {
            name: None,
            listen: None,
            screen: vec![
                ScreenConfig::new("older-name", Cell::ORIGIN),
                ScreenConfig::new(hostname(), Cell::new(1, 0)).with_key("a".repeat(64)),
            ],
            ..Config::default()
        };

        assert_eq!(config.repair_local(), Repair::None, "left alone");
        assert_eq!(config.screen[0].name, "older-name");
        assert!(config.screen[0].key.is_none(), "and still ours");
    }

    #[test]
    fn a_keyless_screen_is_this_machine_under_an_older_name() {
        // The reported bug. Renaming in place keeps the cell, so the neighbour
        // it had yesterday is the neighbour it has now.
        let mut config = orphaned_desk();

        let repair = config.repair_local();

        assert_eq!(
            repair,
            Repair::Renamed {
                from: "this-machine".to_owned()
            }
        );
        assert_eq!(config.screen[0].name, hostname());
        assert_eq!(config.screen[0].at, Cell::ORIGIN, "the cell survives");
        assert_eq!(
            config.grid().neighbours(&hostname()).count(),
            1,
            "and so does the neighbour"
        );
        assert!(config.validate().is_ok(), "and the desk now validates");
    }

    #[test]
    fn a_repair_writes_down_what_this_machine_is_called() {
        // Without the anchor the next hostname change orphans it all over again.
        let mut config = orphaned_desk();

        config.repair_local();

        assert_eq!(config.name.as_deref(), Some(hostname().as_str()));
    }

    #[test]
    fn a_desk_of_peers_only_gains_a_screen_for_this_machine() {
        // Every screen belongs to somebody else, so there is nothing to rename.
        let mut config = Config {
            name: None,
            listen: None,
            screen: vec![
                ScreenConfig::new("forge", Cell::ORIGIN).with_key("a".repeat(64)),
                ScreenConfig::new("tablet", Cell::new(1, 0)).with_key("b".repeat(64)),
            ],
            ..Config::default()
        };

        let repair = config.repair_local();

        assert!(matches!(repair, Repair::Added { .. }));
        assert!(config.validate().is_ok());
        assert!(
            config.stranded().is_empty(),
            "a screen the cursor cannot reach would be no repair at all"
        );
    }

    #[test]
    fn several_keyless_screens_are_left_alone_rather_than_guessed_at() {
        // Only a hand-edited file gets here, and renaming the wrong screen
        // would be worse than adding one.
        let mut config = Config {
            name: None,
            listen: None,
            screen: vec![
                ScreenConfig::new("one", Cell::ORIGIN),
                ScreenConfig::new("two", Cell::new(1, 0)),
            ],
            ..Config::default()
        };

        let repair = config.repair_local();

        assert!(matches!(repair, Repair::Added { .. }));
        assert_eq!(config.screen.iter().filter(|s| s.name == "one").count(), 1);
        assert_eq!(config.screen.iter().filter(|s| s.name == "two").count(), 1);
    }

    #[test]
    fn a_healthy_desk_is_only_anchored() {
        // The migration back-fill, and why the repair runs even when nothing
        // looks wrong.
        let mut config = Config {
            name: None,
            ..desk(&hostname())
        };
        config.screen[0].name = hostname();

        assert_eq!(config.repair_local(), Repair::Anchored);
        assert_eq!(config.name.as_deref(), Some(hostname().as_str()));
        assert_eq!(config.repair_local(), Repair::None, "and only once");
    }

    #[test]
    fn an_empty_desk_gains_no_screen() {
        // A machine that only receives input needs no screen of its own.
        let mut config = Config::default();

        assert_eq!(config.repair_local(), Repair::None);
        assert!(config.screen.is_empty());
    }

    #[test]
    fn placing_a_screen_writes_down_what_this_machine_is_called() {
        let mut config = Config::default();

        config.place("forge", Cell::new(1, 0), None).unwrap();

        assert_eq!(config.name.as_deref(), Some(hostname().as_str()));
    }

    #[test]
    fn a_second_placement_does_not_rewrite_the_name() {
        // A name set by hand has to survive, which is what get_or_insert_with
        // buys over an assignment.
        let mut config = Config {
            name: Some("chosen".to_owned()),
            ..Config::default()
        };

        config.place("forge", Cell::new(1, 0), None).unwrap();

        assert_eq!(config.name.as_deref(), Some("chosen"));
    }

    fn peer(name: &str, byte: u8) -> Peer {
        Peer {
            name: name.to_owned(),
            key: encode_hex(&[byte; 32]),
            address: None,
        }
    }

    #[test]
    fn a_machine_finds_a_name_for_itself() {
        // zsh does not export HOSTNAME and macOS has no /etc/hostname, so a
        // Mac reaches the fallback unless something else answers. Both desks
        // then read "this-machine", which is not a name anybody can act on.
        let name = hostname();

        assert!(!name.is_empty());
        assert!(
            !name.contains(char::is_whitespace),
            "a hostname is one word, got {name:?}"
        );
    }

    #[test]
    fn a_name_is_one_label_whatever_the_system_answered() {
        // macOS answers with the Bonjour name and plenty of Linux boxes answer
        // with the FQDN. A dotted name on the desk is what stopped a Mac from
        // finding its own screen: it had been paired as one name and started
        // calling itself another.
        assert_eq!(first_label("ember.forge.computer"), "ember");
        assert_eq!(first_label("ember.local"), "ember");
        assert_eq!(first_label("ember"), "ember");
    }

    #[test]
    fn a_repeated_suffix_does_not_confuse_the_shortening() {
        // trim_end_matches, which this replaced, strips as many copies as it
        // finds and would have turned this into "a".
        assert_eq!(first_label("a.local.local"), "a");
    }

    #[test]
    fn whatever_the_system_answered_reaches_the_desk_undotted() {
        // The property that matters, asserted against the real machine rather
        // than a fixture: a dot here is a desk that cannot be validated.
        assert!(!hostname().contains('.'), "got {:?}", hostname());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0xab_u8; 32];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes));
    }

    #[test]
    fn a_key_of_the_wrong_length_does_not_decode() {
        assert_eq!(decode_hex(""), None);
        assert_eq!(decode_hex("ab"), None);
        assert_eq!(decode_hex(&"a".repeat(63)), None);
        assert_eq!(decode_hex(&"a".repeat(65)), None);
    }

    #[test]
    fn a_key_with_non_hex_characters_does_not_decode() {
        assert_eq!(decode_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn an_absent_trust_store_reads_as_empty() {
        // A machine that has not paired yet is normal, not broken.
        let path = temp_path("peers.toml");

        assert!(Peers::load(&path).unwrap().peer.is_empty());
    }

    #[test]
    fn a_trust_store_survives_a_round_trip() {
        let path = temp_path("peers.toml");
        let mut peers = Peers::default();
        peers.upsert(peer("laptop", 7));

        peers.save(&path).unwrap();
        let loaded = Peers::load(&path).unwrap();

        assert_eq!(loaded.peer.len(), 1);
        assert_eq!(loaded.peer[0].name, "laptop");
        assert_eq!(loaded.trusted().len(), 1);
    }

    #[test]
    fn re_pairing_the_same_machine_updates_rather_than_duplicates() {
        // A renamed machine is still the same machine, and a second entry for
        // one key would be a second identity to trust for no reason.
        let mut peers = Peers::default();
        peers.upsert(peer("laptop", 7));
        peers.upsert(Peer {
            name: "the-laptop".to_owned(),
            ..peer("x", 7)
        });

        assert_eq!(peers.peer.len(), 1);
        assert_eq!(peers.peer[0].name, "the-laptop");
    }

    #[test]
    fn two_different_machines_both_persist() {
        let mut peers = Peers::default();
        peers.upsert(peer("laptop", 7));
        peers.upsert(peer("desktop", 8));

        assert_eq!(peers.trusted().len(), 2);
    }

    #[test]
    fn a_malformed_key_is_skipped_rather_than_failing_the_whole_store() {
        // Refusing to start because one line is corrupt would take out every
        // working pairing alongside the broken one.
        let mut peers = Peers::default();
        peers.upsert(peer("good", 7));
        peers.upsert(Peer {
            name: "bad".to_owned(),
            key: "nonsense".to_owned(),
            address: None,
        });

        assert_eq!(peers.trusted().len(), 1, "the good peer should survive");
    }

    #[test]
    fn removing_a_peer_by_name_reports_whether_it_existed() {
        let mut peers = Peers::default();
        peers.upsert(peer("laptop", 7));

        assert!(peers.remove_named("laptop"));
        assert!(
            !peers.remove_named("laptop"),
            "a second removal finds nothing"
        );
        assert!(peers.peer.is_empty());
    }

    #[test]
    fn a_desk_survives_a_round_trip_through_disk() {
        // Written by pairing and by the window, so a lossy round trip would
        // quietly rearrange someone's desk.
        let path = temp_path("config.toml");
        let config = desk("desktop");

        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(loaded.grid(), config.grid());
        assert_eq!(loaded.local_name(), "desktop");
    }

    #[test]
    fn the_derived_edges_survive_a_round_trip() {
        // The grid is the storage, but the edges are what the cursor uses.
        let path = temp_path("config.toml");
        desk("desktop").save(&path).unwrap();

        let grid = Config::load(&path).unwrap().grid();
        let neighbours: Vec<_> = grid.neighbours("desktop").collect();

        assert_eq!(neighbours, vec![(Edge::Right, "laptop")]);
    }

    #[test]
    fn an_identity_key_survives_a_round_trip() {
        // It is what makes a rename harmless, so losing it would reintroduce
        // the fragility it exists to remove.
        let path = temp_path("config.toml");
        let mut config = desk("desktop");
        config.screen[1].key = Some("a".repeat(64));

        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(
            loaded
                .screen_for_key(&"a".repeat(64))
                .map(|s| s.name.as_str()),
            Some("laptop")
        );
    }

    #[test]
    fn a_valid_desk_passes() {
        assert!(desk("desktop").validate().is_ok());
    }

    #[test]
    fn a_duplicate_screen_is_rejected() {
        let mut config = desk("desktop");
        config
            .screen
            .push(ScreenConfig::new("desktop", Cell::new(5, 5)));

        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateScreen(_))
        ));
    }

    #[test]
    fn two_screens_on_one_cell_are_rejected() {
        // A hand-edited file can do this, and the cursor would have nowhere
        // unambiguous to land.
        let mut config = desk("desktop");
        config
            .screen
            .push(ScreenConfig::new("tablet", Cell::new(1, 0)));

        assert!(matches!(
            config.validate(),
            Err(ConfigError::SharedCell { .. })
        ));
    }

    #[test]
    fn a_desk_without_this_machine_is_rejected() {
        // Otherwise the cursor has nowhere to start and the failure appears
        // much later as nothing happening at all.
        let config = desk("somewhere-else");

        assert!(matches!(
            config.validate(),
            Err(ConfigError::NoLocalScreen(_))
        ));
    }

    #[test]
    fn an_empty_desk_is_valid() {
        // A machine that only ever receives input needs no desk of its own.
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn placing_the_first_peer_adds_this_machine_too() {
        // A desk with a peer and no local screen is not a desk.
        let mut config = Config {
            name: Some("mac".to_owned()),
            ..Config::default()
        };

        config.place("ubuntu", Cell::new(1, 0), None).unwrap();

        assert_eq!(config.grid().cell_of("mac"), Some(Cell::ORIGIN));
        assert_eq!(config.grid().cell_of("ubuntu"), Some(Cell::new(1, 0)));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn placing_records_the_identity_alongside_the_name() {
        let mut config = Config {
            name: Some("mac".to_owned()),
            ..Config::default()
        };

        config
            .place("ubuntu", Cell::new(1, 0), Some(&"b".repeat(64)))
            .unwrap();

        assert_eq!(
            config
                .screen_for_key(&"b".repeat(64))
                .map(|screen| screen.name.as_str()),
            Some("ubuntu")
        );
    }

    #[test]
    fn placing_onto_an_occupied_cell_is_refused() {
        let mut config = desk("desktop");

        assert!(config.place("tablet", Cell::new(1, 0), None).is_err());
    }

    #[test]
    fn moving_a_screen_leaves_the_desk_valid() {
        let mut config = desk("desktop");

        config.place("laptop", Cell::new(0, 1), None).unwrap();

        assert_eq!(config.grid().cell_of("laptop"), Some(Cell::new(0, 1)));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn applying_a_grid_drops_what_it_no_longer_mentions() {
        let mut config = desk("desktop");
        let mut grid = config.grid();
        grid.remove("laptop");

        config.apply(&grid);

        assert_eq!(config.screen.len(), 1);
        assert_eq!(config.screen[0].name, "desktop");
    }

    #[test]
    fn applying_a_grid_writes_screens_in_a_stable_order() {
        // The file is rewritten on every drag, and a diff should show what
        // moved rather than what was reshuffled.
        let mut config = Config {
            name: Some("m".to_owned()),
            ..Config::default()
        };
        let grid = Grid::of([
            ("zed".to_owned(), Cell::new(2, 0)),
            ("alpha".to_owned(), Cell::ORIGIN),
        ]);

        config.apply(&grid);

        let names: Vec<_> = config.screen.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zed"]);
    }

    #[test]
    fn a_stranded_screen_is_reported() {
        // It looks placed and can never receive the cursor.
        let mut config = desk("desktop");
        config
            .screen
            .push(ScreenConfig::new("island", Cell::new(9, 9)));

        assert_eq!(config.stranded(), vec!["island".to_owned()]);
    }

    #[test]
    fn a_joined_desk_strands_nothing() {
        assert!(desk("desktop").stranded().is_empty());
    }

    #[test]
    fn an_old_edge_style_desk_says_what_to_do_about_it() {
        // The format changed and only one machine in the world had a file. The
        // serde error alone would say "missing field `at`", which tells a user
        // nothing they can act on.
        let path = temp_path("config.toml");
        fs::write(
            &path,
            "name = \"mac\"\n\n[[screen]]\nname = \"mac\"\nright = \"ubuntu\"\n",
        )
        .unwrap();

        let error = Config::load(&path).unwrap_err().to_string();

        assert!(
            error.contains("wraith pair"),
            "the error does not say what to do: {error}"
        );
    }
}
