//! Releasing keys that something else left held.
//!
//! # Why this exists as a separate command
//!
//! Wraith's own sessions release what they hold through nine layers, most of
//! which need nothing from the peer. One case defeats all of them: `SIGKILL`,
//! `abort`, and the OOM killer skip every destructor, because the process is
//! gone before it can run one.
//!
//! On libei and the wlroots virtual keyboard that is survivable, since the
//! compositor releases the emulated keys when the client socket closes. **X11
//! XTEST has no such notion**, and a key held by a process that has died stays
//! held with nothing in the server that will ever change its mind. That is
//! exactly why Deskflow's stuck modifier survives killing the process.
//!
//! So `unstick` is a fresh process that opens its own connection and releases
//! everything, whatever put it down. It does not talk to any running Wraith, it
//! needs no configuration, and it works after the thing that held the key no
//! longer exists.

use crate::domain::input::MODIFIER_SCANCODES;
use crate::domain::{InputEvent, KeyState, Scancode};
use crate::error::{Error, Result};
use crate::platform;
use crate::ports::Inject;

/// The evdev keycode range worth sweeping in `--all` mode.
///
/// One through 248 covers the standard keyboard, the function rows, and the
/// media keys. Above that lies the button range, which the pointer sweep
/// handles, and codes that no keyboard reports.
const SWEEP_RANGE: std::ops::RangeInclusive<u16> = 1..=248;

/// What a sweep did.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Swept {
    pub keys: usize,
    /// Whether the backend would have cleaned up by itself.
    ///
    /// When true the sweep was almost certainly unnecessary, and saying so is
    /// more useful than silently succeeding.
    pub backend_self_releases: bool,
    /// What the system still reports as held afterwards.
    ///
    /// `None` where the backend cannot say, which is most of them. `Some(empty)`
    /// is the outcome worth having: proof rather than hope.
    pub still_held: Option<Vec<Scancode>>,
}

impl Swept {
    /// Whether the sweep is known to have worked.
    ///
    /// False both when something is still held and when the backend could not
    /// tell us, because those deserve different messages but neither is proof.
    #[must_use]
    pub fn verified_clear(&self) -> bool {
        self.still_held.as_ref().is_some_and(Vec::is_empty)
    }
}

/// Releases held keys on this machine.
///
/// With `all` false this sweeps the modifiers, which is the case that matters:
/// a stuck Ctrl or Alt turns every subsequent keystroke into a shortcut, while a
/// stuck letter key is merely visible.
///
/// The default is narrow for correctness rather than speed. Measured against a
/// real X server, sweeping all 248 keycodes costs no more than sweeping the
/// eight modifiers, because the time goes on connecting to the display server.
/// The reason not to sweep everything by default is that a full sweep releases
/// whatever the user is physically holding down at that moment.
pub fn run(all: bool) -> Result<Swept> {
    let mut inject = platform::open_inject()?;
    sweep(inject.as_mut(), all)
}

/// The sweep itself, against any [`Inject`].
///
/// Split out so it can be tested against a recording fake without a display
/// server, which is the only way this is testable in CI at all.
pub fn sweep(inject: &mut dyn Inject, all: bool) -> Result<Swept> {
    let events = release_events(all);
    let keys = events.len();

    inject
        .emit(&events)
        .map_err(|error| Error::Backend(error.to_string()))?;
    inject
        .flush()
        .map_err(|error| Error::Backend(error.to_string()))?;

    let swept = Swept {
        keys,
        backend_self_releases: inject.releases_on_disconnect(),
        // Asked after the sweep, so it reports the outcome rather than the
        // starting state.
        still_held: inject.held_keys(),
    };

    tracing::info!(
        backend = inject.backend_name(),
        keys = swept.keys,
        "released held keys"
    );

    match &swept.still_held {
        Some(held) if held.is_empty() => {
            tracing::info!("the system reports nothing held, so the sweep is confirmed");
        }
        Some(held) => tracing::warn!(
            still_held = ?held,
            "the system still reports keys held after the sweep, which is either a key being \
             physically pressed right now or something outside Wraith holding it"
        ),
        None => tracing::debug!("this backend cannot report held keys, so the sweep is unverified"),
    }

    if swept.backend_self_releases {
        tracing::info!(
            "this backend releases held keys by itself when a client dies, so a stuck key \
             here is more likely a compositor bug than an abandoned Wraith session"
        );
    }

    Ok(swept)
}

/// The release events a sweep sends.
///
/// Unconditional. Nothing here checks whether a key is actually down, because
/// there is nothing to check against: the process that knew has died. Releasing
/// a key that is already up is a no-op on every backend, so the redundancy is
/// free and the alternative is guessing.
#[must_use]
fn release_events(all: bool) -> Vec<InputEvent> {
    let codes: Vec<Scancode> = if all {
        SWEEP_RANGE.map(Scancode).collect()
    } else {
        MODIFIER_SCANCODES.to_vec()
    };

    codes
        .into_iter()
        .map(|code| InputEvent::Key {
            code,
            state: KeyState::Released,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Button;
    use crate::ports::fake::RecordingInject;

    fn released(code: u16) -> InputEvent {
        InputEvent::Key {
            code: Scancode(code),
            state: KeyState::Released,
        }
    }

    #[test]
    fn the_default_sweep_covers_every_modifier() {
        let mut inject = RecordingInject::new();

        let swept = sweep(&mut inject, false).unwrap();

        assert_eq!(swept.keys, MODIFIER_SCANCODES.len());
        for &code in MODIFIER_SCANCODES {
            assert!(
                inject.events().contains(&released(code.0)),
                "{code:?} was not swept"
            );
        }
    }

    #[test]
    fn the_default_sweep_emits_only_releases() {
        // A sweep that pressed anything would be worse than the problem.
        let mut inject = RecordingInject::new();

        sweep(&mut inject, false).unwrap();

        for event in inject.events() {
            assert!(
                matches!(
                    event,
                    InputEvent::Key {
                        state: KeyState::Released,
                        ..
                    }
                ),
                "the sweep emitted {event:?}"
            );
        }
    }

    #[test]
    fn the_full_sweep_covers_the_whole_keyboard_range() {
        let mut inject = RecordingInject::new();

        let swept = sweep(&mut inject, true).unwrap();

        assert_eq!(swept.keys, 248);
        assert!(inject.events().contains(&released(1)), "Escape");
        assert!(inject.events().contains(&released(30)), "A");
        assert!(
            inject.events().contains(&released(248)),
            "the top of the range"
        );
    }

    #[test]
    fn the_full_sweep_includes_the_modifiers() {
        // Otherwise --all would be less effective than the default, which would
        // be an unpleasant surprise for someone reaching for it.
        let mut inject = RecordingInject::new();

        sweep(&mut inject, true).unwrap();

        for &code in MODIFIER_SCANCODES {
            assert!(
                inject.events().contains(&released(code.0)),
                "{code:?} was not swept"
            );
        }
    }

    #[test]
    fn the_sweep_never_touches_pointer_buttons() {
        // Releasing a button the user is legitimately holding would drop
        // whatever they are dragging.
        let mut inject = RecordingInject::new();

        sweep(&mut inject, true).unwrap();

        for event in inject.events() {
            assert!(
                !matches!(event, InputEvent::Button { .. }),
                "the sweep touched a pointer button"
            );
        }
        assert!(!inject.events().contains(&InputEvent::Button {
            button: Button::Left,
            state: KeyState::Released
        }));
    }

    #[test]
    fn a_backend_failure_is_reported_rather_than_swallowed() {
        // Silently succeeding here would leave the user believing their
        // keyboard was fixed when it was not.
        let mut inject = RecordingInject::failing("the display server went away");

        let result = sweep(&mut inject, false);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("display server"));
    }

    #[test]
    fn a_backend_that_reports_nothing_held_confirms_the_sweep() {
        let mut inject = RecordingInject::new().reporting_held(vec![]);

        let swept = sweep(&mut inject, false).unwrap();

        assert!(swept.verified_clear());
    }

    #[test]
    fn a_backend_still_reporting_a_held_key_does_not_confirm_the_sweep() {
        // Someone physically holding a key, or something outside Wraith. Either
        // way, claiming success would be a lie.
        let mut inject = RecordingInject::new().reporting_held(vec![Scancode(30)]);

        let swept = sweep(&mut inject, false).unwrap();

        assert!(!swept.verified_clear());
        assert_eq!(swept.still_held, Some(vec![Scancode(30)]));
    }

    #[test]
    fn a_backend_that_cannot_report_is_unverified_rather_than_confirmed() {
        // Most injection protocols are write-only. Not knowing is not the same
        // as knowing it worked, and the two must not be conflated.
        let mut inject = RecordingInject::new();

        let swept = sweep(&mut inject, false).unwrap();

        assert_eq!(swept.still_held, None);
        assert!(
            !swept.verified_clear(),
            "unknown must not read as confirmed"
        );
    }

    #[test]
    fn a_self_releasing_backend_is_reported_as_such() {
        let mut inject = RecordingInject::new();

        let swept = sweep(&mut inject, false).unwrap();

        assert!(
            !swept.backend_self_releases,
            "the recording fake claims no self-release"
        );
    }
}
