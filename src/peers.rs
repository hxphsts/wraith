//! `wraith peers`, showing who this machine has paired with.

use crate::config::{Config, Peers};
use crate::error::{Error, Result};
use crate::status::short_key;

/// Lists the trust store.
pub(crate) fn list() -> Result<()> {
    let path = Peers::path();
    let peers = Peers::load(&path).map_err(|error| Error::Config(error.to_string()))?;

    if peers.peer.is_empty() {
        println!("no paired machines");
        println!();
        println!("pair one with:");
        println!("    wraith pair                     on this machine");
        println!("    wraith pair --join <address>    on the other");
        return Ok(());
    }

    for peer in &peers.peer {
        let reachable = peer.address.as_deref().unwrap_or("discovered");
        println!(
            "{:<20} {:<18} {}",
            peer.name,
            reachable,
            short_key(&peer.key)
        );
    }

    Ok(())
}

/// What forgetting a machine removed.
#[derive(Debug)]
pub struct Forgotten {
    pub name: String,
    /// Whether a screen came off the desk too.
    pub unplaced: bool,
}

/// Removes a machine from the trust store **and** from the desk.
///
/// Both files. A peer dropped from the trust store but left on the desk gives
/// the cursor an edge it can cross and never come back from, and the layout
/// refuses to build at all once the name resolves to nothing.
pub fn forget_named(name: &str) -> Result<Forgotten> {
    let peers_path = Peers::path();
    let mut peers = Peers::load(&peers_path).map_err(|error| Error::Config(error.to_string()))?;

    // Read before the removal, since it is how the screen is found.
    let key = peers.find(name).map(|peer| peer.key.clone());

    if !peers.remove_named(name) {
        return Err(Error::Config(format!("no paired machine is called {name}")));
    }
    peers
        .save(&peers_path)
        .map_err(|error| Error::Config(error.to_string()))?;

    let unplaced = unplace(name, key.as_deref())?;

    Ok(Forgotten {
        name: name.to_owned(),
        unplaced,
    })
}

/// Takes a forgotten machine's screen off the desk.
///
/// By key first, name second, matching how the session resolves a peer. A
/// machine renamed on its own side is still here under the old name, and
/// matching only the name would leave its screen behind.
fn unplace(name: &str, key: Option<&str>) -> Result<bool> {
    let path = Config::path();
    let mut config = Config::load(&path).map_err(|error| Error::Config(error.to_string()))?;

    let screen = key
        .and_then(|key| config.screen_for_key(key))
        .map_or_else(|| name.to_owned(), |screen| screen.name.clone());

    let mut grid = config.grid();
    if !grid.remove(&screen) {
        return Ok(false);
    }

    config.apply(&grid);
    config
        .save(&path)
        .map_err(|error| Error::Config(error.to_string()))?;

    // Deliberately not compacted. Forgetting the middle of a row strands the
    // far screen, but moving somebody's other machines because they forgot a
    // different one is worse than leaving the gap. The window already draws it.
    let stranded = config.stranded();
    if !stranded.is_empty() {
        tracing::warn!(?stranded, "these screens are no longer reachable from here");
    }

    Ok(true)
}

/// Removes a peer, which is the only way to untrust one.
pub(crate) fn forget(name: &str) -> Result<()> {
    let forgotten = forget_named(name)?;

    println!("forgot {}", forgotten.name);
    if forgotten.unplaced {
        println!("and took its screen off the desk");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_shortened_for_display() {
        assert_eq!(short_key(&"a".repeat(64)), "aaaaaaaaaaaaaaaa");
    }

    #[test]
    fn a_short_key_is_shown_whole_rather_than_panicking() {
        // A malformed store should not take out the command that would show you
        // it is malformed.
        assert_eq!(short_key("abc"), "abc");
        assert_eq!(short_key(""), "");
    }
}
