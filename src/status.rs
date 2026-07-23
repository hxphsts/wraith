//! What a machine is doing, as something to show.
//!
//! Kept apart from any drawing, and in the library rather than the app, because
//! the four states below are a product decision rather than a rendering one.
//! `explain` in particular is the copy a person actually reads when something
//! is wrong, and it belongs where it can be tested with no window at all.
//!
//! The grid is not derived here. The config stores cells, so `Config::grid` is
//! the whole of it, and this module is left with the peer list. Deriving a
//! layout by walking declared neighbours outward from the local machine means
//! two statements of one fact with nothing checking they agree. See
//! `crate::domain::grid`.

use std::collections::BTreeSet;

use crate::config::{Config, Peer, Peers};

/// How a peer is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealth {
    /// Paired and reachable.
    Connected,
    /// Paired, but not answering.
    Unreachable,
    /// Paired, but nowhere on the desk, so the cursor can never reach it.
    NotOnDesk,
    /// Paired and placed, and nothing is running to say either way.
    ///
    /// Distinct from `Unreachable`, which means a session **is** running and
    /// this machine is not answering it. Collapsing the two is what made every
    /// peer read "not answering, check it is running" on a machine that was not
    /// sharing at all, which sent people to check a network that was fine.
    Unknown,
}

impl PeerHealth {
    /// A phrase, not a word.
    ///
    /// "Unreachable" alone leaves a user guessing. What they need is the next
    /// thing to try.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Unreachable => "not answering, check it is running",
            Self::NotOnDesk => "paired but not placed, drag it onto the desk",
            Self::Unknown => "paired, but nothing is sharing on this machine yet",
        }
    }
}

/// A peer as the window shows it.
///
/// `health` is the headline, and the two fields beside it are the facts it was
/// derived from. They are kept because `health` is lossy on purpose: it reports
/// a placement problem before a network one, so an unplaced machine cannot say
/// whether it is even switched on. A window wants both axes, and they are free.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PeerRow {
    pub name: String,
    pub short_key: String,
    pub health: PeerHealth,

    /// Whether this machine has somewhere on the desk to be reached at.
    pub placed: bool,

    /// Whether a connection to it is live right now.
    ///
    /// `None` means nothing is sharing here, so the question has no answer.
    /// That is a different thing from `Some(false)`, which means this machine
    /// is trying and getting nowhere, and conflating them once told everyone
    /// their network was broken when they simply had not started sharing.
    pub online: Option<bool>,
}

/// Every paired peer, with what is wrong where something is.
#[must_use]
pub fn peer_rows(
    peers: &Peers,
    config: &Config,
    connected: Option<&BTreeSet<String>>,
) -> Vec<PeerRow> {
    peers
        .peer
        .iter()
        .map(|peer| PeerRow {
            name: peer.name.clone(),
            short_key: short_key(&peer.key).to_owned(),
            health: health_of(peer, config, connected),
            placed: is_placed(peer, config),
            online: connected.map(|keys| keys.contains(&peer.key)),
        })
        .collect()
}

/// Whether a peer has a screen on the desk.
///
/// By identity first, so a machine renamed on its own side does not appear to
/// have fallen off this one's desk.
fn is_placed(peer: &Peer, config: &Config) -> bool {
    config.screen_for_key(&peer.key).is_some()
        || config.screen.iter().any(|screen| screen.name == peer.name)
}

fn health_of(peer: &Peer, config: &Config, connected: Option<&BTreeSet<String>>) -> PeerHealth {
    if !is_placed(peer, config) {
        // Checked before reachability, because a peer that is not on the desk
        // is a placement problem and "not answering" would send the user to
        // check the network instead.
        return PeerHealth::NotOnDesk;
    }
    // By key, since a status carries keys and a machine may have been renamed
    // on its own side.
    match connected {
        None => PeerHealth::Unknown,
        Some(keys) if keys.contains(&peer.key) => PeerHealth::Connected,
        Some(_) => PeerHealth::Unreachable,
    }
}

/// The first sixteen characters of a key, or all of it if it is shorter.
///
/// `get` rather than a slice because nothing validates key length on the way in:
/// `Peers::load` keeps a malformed entry so one corrupt line cannot take out
/// every working pairing, and a status carries whatever was on disk. Slicing
/// panics on a truncated key, and on a char boundary for a non ASCII one.
pub(crate) fn short_key(key: &str) -> &str {
    key.get(..16).unwrap_or(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScreenConfig;
    use crate::domain::Cell;

    /// A desktop with a laptop to its right.
    fn desk() -> Config {
        Config {
            name: Some("desktop".to_owned()),
            listen: None,
            screen: vec![
                ScreenConfig::new("desktop", Cell::ORIGIN),
                ScreenConfig::new("laptop", Cell::new(1, 0)),
            ],
            ..Config::default()
        }
    }

    /// A running session that reports these keys as answering.
    fn answering(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    fn peer(name: &str) -> Peer {
        Peer {
            name: name.to_owned(),
            key: "a".repeat(64),
            address: None,
        }
    }

    #[test]
    fn a_connected_peer_reads_as_connected() {
        let peers = Peers {
            peer: vec![peer("laptop")],
        };

        let rows = peer_rows(
            &peers,
            &desk(),
            Some(&answering(&["a".repeat(64).as_str()])),
        );

        assert_eq!(rows[0].health, PeerHealth::Connected);
    }

    #[test]
    fn a_silent_peer_reads_as_unreachable() {
        let peers = Peers {
            peer: vec![peer("laptop")],
        };

        let rows = peer_rows(&peers, &desk(), Some(&answering(&[])));

        assert_eq!(rows[0].health, PeerHealth::Unreachable);
    }

    #[test]
    fn a_peer_missing_from_the_desk_says_so_rather_than_unreachable() {
        // The likeliest state right after pairing a third machine, and telling
        // the user to check the network would send them somewhere useless.
        let peers = Peers {
            peer: vec![peer("tablet")],
        };

        let rows = peer_rows(&peers, &desk(), Some(&answering(&[])));

        assert_eq!(rows[0].health, PeerHealth::NotOnDesk);
    }

    #[test]
    fn a_placement_problem_is_reported_before_a_network_one() {
        // A peer both absent from the desk and not answering has one useful
        // thing to say, and it is the desk.
        let peers = Peers {
            peer: vec![peer("tablet")],
        };

        let rows = peer_rows(
            &peers,
            &desk(),
            Some(&answering(&["a".repeat(64).as_str()])),
        );

        assert_eq!(rows[0].health, PeerHealth::NotOnDesk);
    }

    #[test]
    fn a_peer_is_matched_by_identity_rather_than_by_name() {
        // A machine renamed on its own side must not silently fall off this
        // one's desk, which is what matching by name alone would do.
        let mut config = desk();
        config.screen[1] = ScreenConfig::new("renamed", Cell::new(1, 0)).with_key("a".repeat(64));

        let rows = peer_rows(
            &Peers {
                peer: vec![peer("laptop")],
            },
            &config,
            Some(&answering(&[])),
        );

        assert_eq!(
            rows[0].health,
            PeerHealth::Unreachable,
            "matched by key, not by name"
        );
    }

    #[test]
    fn nothing_running_reads_as_unknown_rather_than_unreachable() {
        // The bug this whole state exists for. `connected` was hardcoded empty,
        // so a machine that was not sharing at all told the user every peer was
        // "not answering, check it is running", sending them to check a network
        // that was fine.
        let peers = Peers {
            peer: vec![peer("laptop")],
        };

        let rows = peer_rows(&peers, &desk(), None);

        assert_eq!(rows[0].health, PeerHealth::Unknown);
        assert!(!rows[0].health.explain().contains("check"));
    }

    #[test]
    fn a_running_session_with_nobody_answering_is_not_the_same_as_no_session() {
        let peers = Peers {
            peer: vec![peer("laptop")],
        };

        let running = peer_rows(&peers, &desk(), Some(&answering(&[])));
        let stopped = peer_rows(&peers, &desk(), None);

        assert_ne!(running[0].health, stopped[0].health);
    }

    #[test]
    fn every_health_explains_the_next_thing_to_try() {
        // "Unreachable" alone leaves the user guessing.
        for health in [
            PeerHealth::Connected,
            PeerHealth::Unreachable,
            PeerHealth::NotOnDesk,
            PeerHealth::Unknown,
        ] {
            assert!(!health.explain().is_empty());
        }
        assert!(PeerHealth::Unreachable.explain().contains("check"));
        assert!(PeerHealth::NotOnDesk.explain().contains("drag"));
    }

    #[test]
    fn a_key_is_shortened_without_panicking_on_a_short_one() {
        assert_eq!(short_key(&peer("x").key).len(), 16);
        assert_eq!(short_key("abc"), "abc");
        assert_eq!(short_key(""), "");

        // A key with a multi-byte character in the first sixteen. Slicing by
        // byte index lands mid character and panics, which a corrupt store
        // should not be able to do to the command that would reveal it.
        assert_eq!(short_key("é"), "é");
    }

    #[test]
    fn an_unplaced_machine_still_says_whether_it_is_online() {
        // The reason the two axes exist. `health` reports the placement problem
        // and stops, which is right for a headline and useless for a dot: an
        // unplaced machine that is switched on and one that is unplugged were
        // indistinguishable.
        let peers = Peers {
            peer: vec![peer("tablet")],
        };

        let up = peer_rows(
            &peers,
            &desk(),
            Some(&answering(&["a".repeat(64).as_str()])),
        );
        let down = peer_rows(&peers, &desk(), Some(&answering(&[])));

        assert_eq!(up[0].health, PeerHealth::NotOnDesk, "still the headline");
        assert_eq!(down[0].health, PeerHealth::NotOnDesk);

        assert_eq!(up[0].online, Some(true), "and yet it is reachable");
        assert_eq!(down[0].online, Some(false));
    }

    #[test]
    fn placed_is_reported_beside_the_health_rather_than_only_inside_it() {
        let placed = peer_rows(
            &Peers {
                peer: vec![peer("laptop")],
            },
            &desk(),
            None,
        );
        let unplaced = peer_rows(
            &Peers {
                peer: vec![peer("tablet")],
            },
            &desk(),
            None,
        );

        assert!(placed[0].placed);
        assert!(!unplaced[0].placed);
    }

    #[test]
    fn online_is_unanswerable_with_nothing_sharing() {
        // None and Some(false) are different claims: "no idea" versus "tried
        // and failed". Collapsing them is what told everyone their network was
        // broken when they had simply not started sharing.
        let rows = peer_rows(
            &Peers {
                peer: vec![peer("laptop")],
            },
            &desk(),
            None,
        );

        assert_eq!(rows[0].online, None);
        assert_eq!(rows[0].health, PeerHealth::Unknown);
    }
}
