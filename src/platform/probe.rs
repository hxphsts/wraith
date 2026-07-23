//! Choosing a backend, and explaining the choice.
//!
//! The decision is a pure function of gathered evidence, deliberately separated
//! from the gathering. [`choose_linux_backend`] has no I/O, so the whole
//! selection matrix is testable as a table with nothing mocked, because there is
//! nothing to mock. [`gather_linux_env`] has all the I/O and no logic.

use std::fmt;

/// What the environment looks like, as far as backend selection cares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinuxEnv {
    /// `XDG_SESSION_TYPE`, typically `wayland`, `x11`, or `tty`.
    pub session_type: Option<String>,
    pub wayland_display: Option<String>,
    pub x11_display: Option<String>,
    /// The `org.freedesktop.portal.RemoteDesktop` interface version, if present.
    ///
    /// Version 2 or later is required, because that is where session
    /// persistence landed. Without it the user re-approves a dialog on every
    /// launch, which is not acceptable for something that runs all day.
    pub portal_remote_desktop_version: Option<u32>,
    /// Whether the compositor offers both wlroots virtual input protocols.
    ///
    /// One flag rather than one per protocol, because the backend needs both
    /// and the probe is a single connect that either succeeds or does not.
    pub has_wlr_virtual_input: bool,

    /// Whether the X server has the XTEST extension.
    ///
    /// Compiled into every mainstream server and disableable, so it is asked
    /// rather than assumed from `DISPLAY`.
    pub has_xtest: bool,
}

/// Which backend to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendChoice {
    /// libei through the portal. GNOME 46 and later, Plasma 6.1 and later.
    LibeiPortal,
    /// The wlroots virtual pointer and keyboard protocols, plus layer shell.
    /// Sway, Hyprland, Wayfire, niri.
    Wlroots,
    /// XTEST and `XInput2`.
    X11,
}

impl fmt::Display for BackendChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // pad rather than write_str, so `{:<14}` in the probe output aligns.
        f.pad(match self {
            Self::LibeiPortal => "libei-portal",
            Self::Wlroots => "wlroots",
            Self::X11 => "x11",
        })
    }
}

/// Why a backend was not chosen.
///
/// Carried so `wraith probe` can tell a user what to change. "Unsupported"
/// alone sends them to an issue tracker rather than to their compositor
/// settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub backend: BackendChoice,
    pub because: String,
}

/// The outcome of probing, including the backends that lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub chosen: Option<BackendChoice>,
    pub rejected: Vec<Rejection>,
}

impl Probe {
    /// A one-line summary of why nothing worked.
    #[must_use]
    pub fn failure_summary(&self) -> String {
        if self.rejected.is_empty() {
            return "no backends were even considered on this platform".to_owned();
        }
        self.rejected
            .iter()
            .map(|r| format!("{}: {}", r.backend, r.because))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Picks a backend from the evidence. Pure.
///
/// Precedence: the portal, then wlroots, then X11.
/// The portal comes first because it is the only path with a supported story on
/// GNOME and KDE, which is most Linux desktops. wlroots comes before X11 because
/// on a wlroots session X11 would only reach `XWayland` clients.
#[must_use]
pub fn choose_linux_backend(env: &LinuxEnv) -> Probe {
    let mut rejected = Vec::new();

    match env.portal_remote_desktop_version {
        Some(version) if version >= 2 => {
            return Probe {
                chosen: Some(BackendChoice::LibeiPortal),
                rejected,
            };
        }
        Some(version) => rejected.push(Rejection {
            backend: BackendChoice::LibeiPortal,
            because: format!(
                "the RemoteDesktop portal is version {version}, and session persistence \
                 needs version 2 or later"
            ),
        }),
        None => rejected.push(Rejection {
            backend: BackendChoice::LibeiPortal,
            because: "no RemoteDesktop portal is running".to_owned(),
        }),
    }

    if env.wayland_display.is_some() {
        if env.has_wlr_virtual_input {
            return Probe {
                chosen: Some(BackendChoice::Wlroots),
                rejected,
            };
        }
        rejected.push(Rejection {
            backend: BackendChoice::Wlroots,
            because: MISSING_WLR_PROTOCOLS.to_owned(),
        });
    } else {
        rejected.push(Rejection {
            backend: BackendChoice::Wlroots,
            because: "not a Wayland session".to_owned(),
        });
    }

    if env.x11_display.is_some() && env.has_xtest {
        return Probe {
            chosen: Some(BackendChoice::X11),
            rejected,
        };
    }
    rejected.push(Rejection {
        backend: BackendChoice::X11,
        because: if env.x11_display.is_none() {
            "DISPLAY is not set".to_owned()
        } else {
            "the X server has no XTEST extension".to_owned()
        },
    });

    Probe {
        chosen: None,
        rejected,
    }
}

/// Why a Wayland session still cannot use the wlroots backend.
///
/// Both protocols, because the backend needs both and the probe cannot tell
/// which is absent. Trying it reports the specific one.
const MISSING_WLR_PROTOCOLS: &str = "the compositor does not offer \
     zwlr_virtual_pointer_manager_v1 and zwp_virtual_keyboard_manager_v1";

/// Reads the environment. All the I/O, none of the logic.
#[must_use]
pub fn gather_linux_env() -> LinuxEnv {
    LinuxEnv {
        session_type: std::env::var("XDG_SESSION_TYPE").ok(),
        wayland_display: std::env::var("WAYLAND_DISPLAY").ok(),
        x11_display: std::env::var("DISPLAY").ok(),
        // Filled in when the portal backend lands. Reporting it absent is
        // honest today: no libei source exists to be chosen.
        portal_remote_desktop_version: None,
        // Probed by asking the compositor, which is the only reliable answer.
        // An environment variable would guess, and Hyprland and GNOME both set
        // WAYLAND_DISPLAY.
        has_wlr_virtual_input: wlr_protocols_present(),
        has_xtest: xtest_present(),
    }
}

/// Whether the compositor offers the wlroots virtual input protocols.
///
/// Answered by connecting and looking, because there is no environment variable
/// that distinguishes Hyprland from GNOME: both set `WAYLAND_DISPLAY`.
#[cfg(target_os = "linux")]
fn wlr_protocols_present() -> bool {
    crate::platform::linux::wlroots::WlrootsInject::open().is_ok()
}

#[cfg(not(target_os = "linux"))]
const fn wlr_protocols_present() -> bool {
    false
}

/// Whether the X server has the XTEST extension.
///
/// Asked rather than inferred from `DISPLAY`. XTEST is compiled into every
/// mainstream server but can be disabled, and inferring it from the variable
/// makes the rejection below unreachable while claiming to have checked.
///
/// A connect and one extension query, with no window and no device created, so
/// unlike the wlroots probe this costs nothing the session will notice.
#[cfg(target_os = "linux")]
fn xtest_present() -> bool {
    use x11rb::connection::RequestConnection as _;

    let Ok((connection, _)) = x11rb::connect(None) else {
        return false;
    };

    connection
        .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)
        .is_ok_and(|found| found.is_some())
}

#[cfg(not(target_os = "linux"))]
const fn xtest_present() -> bool {
    false
}

/// Prints what Wraith makes of this machine.
///
/// Lives here rather than in the command that calls it, because the answer is
/// per-platform and `platform` is the one module allowed to say so. A `#[cfg]`
/// anywhere else is a leak, and moving the printing was cheaper than inventing
/// a port for it.
///
/// Every platform reports the same three sections, so one command answers "why
/// is this not working" wherever it is asked. Which backend was chosen is the
/// interesting part on Linux, where there are several; the grants are the
/// interesting part on macOS, where there is one backend and two ways to be
/// refused.
#[cfg(target_os = "linux")]
pub fn report() -> crate::error::Result<()> {
    let env = gather_linux_env();
    let outcome = choose_linux_backend(&env);

    println!("session");
    println!(
        "  type          {}",
        env.session_type.as_deref().unwrap_or("unknown")
    );
    println!(
        "  wayland       {}",
        env.wayland_display.as_deref().unwrap_or("not set")
    );
    println!(
        "  x11           {}",
        env.x11_display.as_deref().unwrap_or("not set")
    );

    println!();
    println!("backends");
    for rejection in &outcome.rejected {
        println!("  {:<14}no     {}", rejection.backend, rejection.because);
    }
    match outcome.chosen {
        Some(backend) => println!("  {backend:<14}yes    chosen"),
        None => println!("  none usable"),
    }

    println!();
    println!("clipboard");
    match outcome.chosen {
        Some(BackendChoice::X11) => println!("  {:<14}yes    follows the cursor", "x11"),
        Some(other) => {
            println!("  {other:<14}no     no clipboard half yet, lands with its capture");
        }
        None => println!("  none           no input backend, so nothing to sync"),
    }

    report_screen();
    report_permissions();
    Ok(())
}

/// Prints what Wraith makes of this machine.
///
/// macOS has one backend and nothing to choose between, so the grants below are
/// the whole of the answer. Capturing and injecting are permitted separately
/// here, and granting one without the other produces a session that starts,
/// connects, reports every peer healthy, and moves nothing.
#[cfg(target_os = "macos")]
pub fn report() -> crate::error::Result<()> {
    println!("session");
    println!("  type          quartz");

    println!();
    println!("backends");
    println!("  {:<14}yes    chosen", "coregraphics");

    println!();
    println!("clipboard");
    println!("  {:<14}yes    follows the cursor", "pasteboard");

    report_screen();
    report_permissions();
    Ok(())
}

/// What this machine tells its peers it is.
///
/// Worth printing because every crossing is measured against it: a peer maps a
/// fraction of an edge onto these numbers, so a machine reporting the wrong
/// size lands the cursor in the wrong place on both sides.
fn report_screen() {
    println!();
    println!("screen");

    match crate::platform::local_screen() {
        Some(screen) => println!("  size          {}x{}", screen.width_px, screen.height_px),
        None => println!("  size          unknown, so peers are told a default"),
    }
}

/// The two grants, and what a withheld one costs.
fn report_permissions() {
    let permissions = crate::platform::permissions();

    println!();
    println!("permissions");
    println!("  inject        {}", describe(permissions.inject));
    println!("  capture       {}", describe(permissions.capture));

    if let Some(why) = permissions.explain() {
        println!();
        println!("{why}");
    }
}

const fn describe(grant: crate::ports::Grant) -> &'static str {
    match grant {
        crate::ports::Grant::Given => "granted",
        crate::ports::Grant::Withheld => "withheld",
        crate::ports::Grant::NotRequired => "not required on this platform",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gnome_wayland() -> LinuxEnv {
        LinuxEnv {
            session_type: Some("wayland".to_owned()),
            wayland_display: Some("wayland-0".to_owned()),
            x11_display: Some(":0".to_owned()), // XWayland is usually running
            portal_remote_desktop_version: Some(2),
            has_xtest: true,
            ..LinuxEnv::default()
        }
    }

    fn hyprland() -> LinuxEnv {
        LinuxEnv {
            session_type: Some("wayland".to_owned()),
            wayland_display: Some("wayland-1".to_owned()),
            x11_display: Some(":0".to_owned()),
            portal_remote_desktop_version: None,
            has_wlr_virtual_input: true,
            has_xtest: true,
        }
    }

    fn plain_x11() -> LinuxEnv {
        LinuxEnv {
            session_type: Some("x11".to_owned()),
            x11_display: Some(":0".to_owned()),
            has_xtest: true,
            ..LinuxEnv::default()
        }
    }

    fn headless() -> LinuxEnv {
        LinuxEnv {
            session_type: Some("tty".to_owned()),
            ..LinuxEnv::default()
        }
    }

    #[test]
    fn gnome_wayland_chooses_the_portal() {
        let probe = choose_linux_backend(&gnome_wayland());
        assert_eq!(probe.chosen, Some(BackendChoice::LibeiPortal));
    }

    #[test]
    fn hyprland_chooses_wlroots() {
        // The undefended niche. Deskflow closes these reports as upstream's
        // problem, so a portal-only design strands every one of these users.
        let probe = choose_linux_backend(&hyprland());
        assert_eq!(probe.chosen, Some(BackendChoice::Wlroots));
    }

    #[test]
    fn a_plain_x11_session_chooses_x11() {
        let probe = choose_linux_backend(&plain_x11());
        assert_eq!(probe.chosen, Some(BackendChoice::X11));
    }

    #[test]
    fn wlroots_wins_over_x11_on_a_wayland_session() {
        // XWayland is running, so X11 would appear usable, but it would only
        // reach XWayland clients and native Wayland windows would see nothing.
        let probe = choose_linux_backend(&hyprland());
        assert_eq!(probe.chosen, Some(BackendChoice::Wlroots));
    }

    #[test]
    fn the_portal_wins_over_wlroots_when_both_are_available() {
        let mut env = gnome_wayland();
        env.has_wlr_virtual_input = true;

        let probe = choose_linux_backend(&env);

        assert_eq!(probe.chosen, Some(BackendChoice::LibeiPortal));
    }

    #[test]
    fn a_portal_older_than_version_two_is_rejected() {
        // Version 2 is where session persistence landed. Without it the user
        // re-approves a dialog every launch.
        let mut env = gnome_wayland();
        env.portal_remote_desktop_version = Some(1);

        let probe = choose_linux_backend(&env);

        assert_ne!(probe.chosen, Some(BackendChoice::LibeiPortal));
        assert!(probe.failure_summary().contains("version 2"));
    }

    #[test]
    fn a_wayland_session_with_neither_portal_nor_wlroots_falls_back_to_x11() {
        let mut env = gnome_wayland();
        env.portal_remote_desktop_version = None;

        let probe = choose_linux_backend(&env);

        assert_eq!(
            probe.chosen,
            Some(BackendChoice::X11),
            "XWayland is better than nothing"
        );
    }

    #[test]
    fn a_headless_session_chooses_nothing() {
        let probe = choose_linux_backend(&headless());
        assert_eq!(probe.chosen, None);
    }

    #[test]
    fn a_failed_probe_explains_every_rejection() {
        // "Unsupported" alone sends a user to an issue tracker. This sends them
        // to their compositor settings.
        let probe = choose_linux_backend(&headless());
        let summary = probe.failure_summary();

        assert_eq!(probe.rejected.len(), 3);
        assert!(summary.contains("libei-portal"));
        assert!(summary.contains("wlroots"));
        assert!(summary.contains("x11"));
    }

    #[test]
    fn a_wayland_session_without_the_protocols_names_them() {
        // A GNOME user needs to be told their compositor does not offer these,
        // rather than that something failed: nothing is broken and they want
        // the portal instead.
        let mut env = hyprland();
        env.has_wlr_virtual_input = false;
        env.portal_remote_desktop_version = None;

        let probe = choose_linux_backend(&env);
        let summary = probe.failure_summary();

        assert_ne!(probe.chosen, Some(BackendChoice::Wlroots));
        assert!(
            summary.contains("zwlr_virtual_pointer_manager_v1"),
            "{summary}"
        );
        assert!(
            summary.contains("zwp_virtual_keyboard_manager_v1"),
            "{summary}"
        );
    }

    #[test]
    fn x11_without_xtest_is_rejected_with_a_reason() {
        let mut env = plain_x11();
        env.has_xtest = false;

        let probe = choose_linux_backend(&env);

        assert_eq!(probe.chosen, None);
        assert!(probe.failure_summary().contains("XTEST"));
    }
}
