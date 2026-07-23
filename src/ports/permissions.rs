//! What this machine will let Wraith do.
//!
//! # Why this is two grants and not one
//!
//! On macOS, capturing input and injecting it are separately permitted.
//! Accessibility allows posting events, Input Monitoring allows observing them,
//! and granting one without the other produces the worst failure this project
//! has: an app that starts, connects, reports every peer healthy, and moves
//! nothing. Nothing in a status can explain that, because from the session's
//! point of view everything is fine.
//!
//! So the two are modelled apart, all the way to the window. Collapsing them
//! into one "permissions ok" is what makes the failure unexplainable.
//!
//! # Why polling and not asking
//!
//! A grant is given in System Settings, in another process, and the app is never
//! told. The only way to know is to ask again. So
//! [`crate::platform::permissions`] is cheap and idempotent and expected to be
//! called on a timer, and it never prompts.
//! [`crate::platform::request_permissions`] is the one that prompts, and is
//! called once, from a button the user pressed.

/// Whether a thing is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Grant {
    /// Allowed. Verified, not assumed.
    Given,

    /// Not allowed, and the user must give it.
    Withheld,

    /// This platform does not gate it, so there is nothing to grant.
    ///
    /// Distinct from `Given` on purpose. A window must not show a Linux user a
    /// green tick for a permission that does not exist there, because the next
    /// question is where they granted it.
    ///
    /// Also the default, which matters for the instant before anything has
    /// looked: a window that assumes `Withheld` until told otherwise flashes a
    /// permissions warning on every launch and then takes it back.
    #[default]
    NotRequired,
}

impl Grant {
    /// Whether this stands in the way of working.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::Withheld)
    }
}

/// One of the two things a platform grants separately.
///
/// Named for what Wraith does rather than for what any one platform calls it,
/// so a window can ask for the settings that govern an ability without knowing
/// whose vocabulary it is asking in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ability {
    /// Posting events.
    Inject,

    /// Observing events.
    Capture,
}

impl Ability {
    /// What the settings call this, for a control that opens them.
    ///
    /// Here rather than in the window for the same reason as
    /// [`Permissions::explain`]: the words have to match the ones on screen in
    /// System Settings, which is a fact about the platform rather than a
    /// rendering choice.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inject => "Accessibility",
            Self::Capture => "Input Monitoring",
        }
    }
}

/// The two grants, together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Permissions {
    /// Posting events. macOS calls this Accessibility.
    ///
    /// Without it the cursor can arrive from another machine and nothing moves.
    pub inject: Grant,

    /// Observing events. macOS calls this Input Monitoring.
    ///
    /// Without it the cursor can never leave this machine, because nothing here
    /// sees the keyboard or the pointer.
    pub capture: Grant,
}

impl Permissions {
    /// Whether sharing can work at all.
    #[must_use]
    pub const fn complete(self) -> bool {
        !self.inject.blocks() && !self.capture.blocks()
    }

    /// A sentence naming what is missing.
    ///
    /// Returns `None` when nothing is. Written here rather than in the window
    /// because which grant is missing decides what breaks, and that is a product
    /// fact rather than a rendering one.
    #[must_use]
    pub const fn explain(self) -> Option<&'static str> {
        match (self.inject.blocks(), self.capture.blocks()) {
            (true, true) => Some(
                "Wraith cannot see this keyboard or move this pointer. \
                 Grant both Accessibility and Input Monitoring",
            ),
            (true, false) => Some(
                "the cursor can arrive here but nothing will move. \
                 Grant Accessibility",
            ),
            (false, true) => Some(
                "the cursor can never leave this machine, because nothing here \
                 sees the keyboard. Grant Input Monitoring",
            ),
            (false, false) => None,
        }
    }

    /// What is missing, as things a person can be sent to give.
    ///
    /// Capture first, because a machine that cannot see the keyboard cannot
    /// start a crossing at all, and the other grant only matters once one
    /// arrives.
    #[must_use]
    pub fn missing(self) -> Vec<Ability> {
        let mut missing = Vec::with_capacity(2);
        if self.capture.blocks() {
            missing.push(Ability::Capture);
        }
        if self.inject.blocks() {
            missing.push(Ability::Inject);
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn both(inject: Grant, capture: Grant) -> Permissions {
        Permissions { inject, capture }
    }

    #[test]
    fn nothing_is_missing_where_nothing_is_gated() {
        assert!(Permissions::default().missing().is_empty());
        assert!(both(Grant::Given, Grant::Given).missing().is_empty());
    }

    #[test]
    fn a_missing_grant_is_offered_capture_first() {
        assert_eq!(
            both(Grant::Withheld, Grant::Withheld).missing(),
            vec![Ability::Capture, Ability::Inject]
        );
        assert_eq!(
            both(Grant::Withheld, Grant::Given).missing(),
            vec![Ability::Inject]
        );
        assert_eq!(
            both(Grant::Given, Grant::Withheld).missing(),
            vec![Ability::Capture]
        );
    }

    #[test]
    fn every_missing_grant_can_be_named_on_a_button() {
        for ability in both(Grant::Withheld, Grant::Withheld).missing() {
            assert!(!ability.label().is_empty());
        }
    }

    #[test]
    fn the_default_makes_no_claim_and_blocks_nothing() {
        // Used for the instant before the first poll answers. Defaulting to
        // withheld would flash a permissions warning on every launch.
        assert_eq!(Permissions::default().inject, Grant::NotRequired);
        assert!(Permissions::default().complete());
        assert!(Permissions::default().explain().is_none());
    }

    #[test]
    fn nothing_to_grant_is_not_the_same_as_granted_but_both_are_fine() {
        // Linux has neither gate. A window must not claim the user granted
        // something they were never asked for, and must also not block on it.
        assert!(!Grant::NotRequired.blocks());
        assert_ne!(Grant::NotRequired, Grant::Given);
        assert!(both(Grant::NotRequired, Grant::NotRequired).complete());
    }

    #[test]
    fn one_grant_alone_is_still_broken() {
        // The failure this whole port exists for: an app that starts, connects,
        // reports every peer healthy, and moves nothing.
        assert!(!both(Grant::Given, Grant::Withheld).complete());
        assert!(!both(Grant::Withheld, Grant::Given).complete());
        assert!(both(Grant::Given, Grant::Given).complete());
    }

    #[test]
    fn each_half_says_what_specifically_breaks() {
        // "Permissions missing" sends someone to a settings pane with two
        // switches and no idea which one. Each case names the symptom first.
        let no_inject = both(Grant::Withheld, Grant::Given)
            .explain()
            .expect("something is missing");
        assert!(no_inject.contains("arrive"), "got {no_inject}");

        let no_capture = both(Grant::Given, Grant::Withheld)
            .explain()
            .expect("something is missing");
        assert!(no_capture.contains("never leave"), "got {no_capture}");

        assert!(no_inject != no_capture, "the two read differently");
    }

    #[test]
    fn a_complete_set_explains_nothing() {
        assert!(both(Grant::Given, Grant::Given).explain().is_none());
        assert!(
            both(Grant::NotRequired, Grant::NotRequired)
                .explain()
                .is_none()
        );
    }
}
