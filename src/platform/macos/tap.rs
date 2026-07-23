//! macOS capture, through a CoreGraphics event tap.
//!
//! # Two permissions, and neither is optional
//!
//! An active tap needs **Input Monitoring**, and posting the events needs
//! **Accessibility**. They are separate grants in separate panes.
//!
//! The usual way to avoid Input Monitoring is
//! `NSEvent.addGlobalMonitorForEventsMatchingMask`, which needs only
//! Accessibility. It does not work here: a global monitor **cannot suppress
//! events**, and a KVM must consume input locally while the cursor is remote.
//! Without suppression this is a keylogger that also moves a pointer.
//!
//! # The signing trap
//!
//! `CGPreflightListenEventAccess` checks the bundle identifier against the TCC
//! database, but `CGEventTapCreate` checks the binary's cdhash against the
//! kernel. On an ad-hoc-signed build every `cargo build` changes the cdhash, so
//! the two disagree and the tap silently re-prompts on every call.
//!
//! Retrying on a timer turns that into an inescapable loop of dialogs. So this
//! creates the tap **once** and reports a failure rather than retrying. Get
//! Developer ID signing working before debugging a permission problem here, or
//! the problem is the signing.
//!
//! # The feedback loop
//!
//! A tap sees the events this machine injects, and there is no device id to
//! filter on as there is under X11. Every injected event is stamped with
//! [`OUR_EVENTS`] on `EventSourceUserData` instead, and anything carrying that
//! stamp is ignored here.
//!
//! Without it a receiving Mac captures its own injection and, with its cursor
//! remote, forwards it back to the machine it came from, which then does the
//! same. Two peers trade one keystroke forever.
//!
//! # Why a dedicated thread
//!
//! A tap delivers through a `CFRunLoop`, which blocks. The [`Capture`] contract
//! is a bounded poll, so the run loop gets its own thread and events cross to
//! the caller over a channel.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::Duration;

use objc2_core_foundation::{
    CFMachPort, CFRetained, CFRunLoop, CFRunLoopSource, kCFRunLoopCommonModes,
};
use objc2_core_graphics::{
    CGEvent, CGEventField, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
};

use super::{OUR_EVENTS, codes};
use crate::domain::{Button, InputEvent, KeyState, Scancode};
use crate::ports::capture::{Capture, CaptureError};

/// How many events may queue before motion starts being dropped.
const QUEUE_CAPACITY: usize = 1_024;

// See the module docs. Not exposed by the bindings.
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn CGPreflightListenEventAccess() -> bool;
    fn CGRequestListenEventAccess() -> bool;
}

/// Captures input on macOS.
///
/// Holds nothing from CoreFoundation. The tap, its run loop source, and its
/// context are all created on the thread that services them and never leave it,
/// so nothing here needs an `unsafe impl Send` and nothing can be touched from
/// two threads by accident.
pub struct MacOsCapture {
    events: Receiver<InputEvent>,
    /// Read by the tap callback to decide whether to swallow an event.
    ///
    /// An atomic rather than a channel, because the callback runs on the run
    /// loop thread and must not block: a callback that takes longer than the
    /// system's timeout is silently disabled, taking capture with it.
    suppressed: Arc<AtomicBool>,
    /// Tells the tap thread to stop swallowing and wind down.
    shutdown: Arc<AtomicBool>,
}

impl std::fmt::Debug for MacOsCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsCapture")
            .field("suppressed", &self.suppressed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// What the tap callback needs, kept alive for the tap's lifetime.
///
/// Lives on the tap thread and is dereferenced only by the callback, which
/// CoreGraphics also runs there.
struct TapContext {
    sender: SyncSender<InputEvent>,
    suppressed: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    /// So the callback can re-enable a tap the system disabled.
    tap: CFRetained<CFMachPort>,
}

impl MacOsCapture {
    /// Creates the tap, prompting for Input Monitoring if it is not granted.
    ///
    /// Once. See the module documentation: retrying is what turns a signing
    /// problem into an endless dialog.
    pub fn open() -> Result<Self, CaptureError> {
        // SAFETY: both take no arguments and return a bool. Preflight first, so
        // an already-granted process never sees a prompt.
        let granted = unsafe { CGPreflightListenEventAccess() || CGRequestListenEventAccess() };

        if !granted {
            return Err(CaptureError::PermissionDenied(
                "Wraith needs Input Monitoring to see input. Grant it in System Settings, \
                 Privacy and Security, Input Monitoring, then start Wraith again"
                    .to_owned(),
            ));
        }

        let (sender, events) = sync_channel(QUEUE_CAPACITY);
        let suppressed = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        // The thread reports whether the tap was created, because everything
        // CoreFoundation hands back has to stay on that thread.
        let (ready, started) = sync_channel(1);

        let thread_state = (sender, Arc::clone(&suppressed), Arc::clone(&shutdown));
        std::thread::Builder::new()
            .name("wraith-macos-tap".to_owned())
            .spawn(move || run_tap(thread_state, &ready))
            .map_err(|error| {
                CaptureError::Backend(format!("cannot start the tap thread: {error}"))
            })?;

        started
            .recv()
            .map_err(|_| CaptureError::Backend("the tap thread stopped at once".to_owned()))??;

        Ok(Self {
            events,
            suppressed,
            shutdown,
        })
    }
}

/// Creates the tap and services it until told to stop.
///
/// Everything CoreFoundation returns is created and destroyed here, so no
/// handle ever crosses a thread and no `unsafe impl Send` is needed.
fn run_tap(
    state: (SyncSender<InputEvent>, Arc<AtomicBool>, Arc<AtomicBool>),
    ready: &SyncSender<Result<(), CaptureError>>,
) {
    let (sender, suppressed, shutdown) = state;

    // Allocated but not yet filled: the context needs the tap, and the tap
    // needs the context pointer, so the pointer is taken first and the tap
    // written into it once created.
    let context = Box::into_raw(Box::new(None::<TapContext>));

    let (tap, source) = match open_tap(context) {
        Ok(both) => both,
        Err(why) => {
            // SAFETY: nothing took ownership, so the box is reclaimed rather
            // than leaked.
            drop(unsafe { Box::from_raw(context) });
            let _ = ready.send(Err(why));
            return;
        }
    };

    // SAFETY: the pointer was just allocated here and nothing else holds it.
    // The callback cannot run yet, because the source is not in a run loop.
    unsafe {
        *context = Some(TapContext {
            sender,
            suppressed,
            shutdown,
            tap: tap.clone(),
        });
    }

    let run_loop = CFRunLoop::current().expect("a thread always has a run loop");
    // SAFETY: the source came from the tap's port, and the mode is a static
    // CoreFoundation constant.
    unsafe {
        CFRunLoop::add_source(&run_loop, Some(&source), kCFRunLoopCommonModes);
    }

    let _ = ready.send(Ok(()));
    CFRunLoop::run();

    // Reached only once the run loop stops, so no callback can be running.
    CGEvent::tap_enable(&tap, false);
    // SAFETY: as above.
    drop(unsafe { Box::from_raw(context) });
}

/// Creates the tap and its run loop source, or explains the refusal.
///
/// Split out so the caller is left with the ownership dance, which is the part
/// worth reading closely. Neither half is filled in on failure: the context box
/// is still the caller's to reclaim.
fn open_tap(
    context: *mut Option<TapContext>,
) -> Result<(CFRetained<CFMachPort>, CFRetained<CFRunLoopSource>), CaptureError> {
    // SAFETY: the callback matches CGEventTapCallBack, and the pointer stays
    // valid for as long as the calling thread runs, which outlives the tap.
    let tap = unsafe {
        CGEvent::tap_create(
            CGEventTapLocation::HIDEventTap,
            CGEventTapPlacement::HeadInsertEventTap,
            // Active rather than ListenOnly. ListenOnly cannot swallow an
            // event, and swallowing is the whole point.
            CGEventTapOptions::Default,
            event_mask(),
            Some(on_event),
            context.cast::<c_void>(),
        )
    };

    let Some(tap) = tap else {
        return Err(CaptureError::PermissionDenied(
            "macOS refused the event tap. This is usually the code signature rather than the \
             permission: an ad-hoc signed build changes its cdhash on every rebuild, and the \
             kernel checks the cdhash even when Settings shows the grant. Sign with a \
             Developer ID"
                .to_owned(),
        ));
    };

    let Some(source) = CFMachPort::new_run_loop_source(None, Some(&tap), 0) else {
        return Err(CaptureError::Backend(
            "cannot create a run loop source for the tap".to_owned(),
        ));
    };

    Ok((tap, source))
}

impl Capture for MacOsCapture {
    fn poll(&mut self, timeout_ms: u32, out: &mut Vec<InputEvent>) -> Result<(), CaptureError> {
        match self
            .events
            .recv_timeout(Duration::from_millis(u64::from(timeout_ms)))
        {
            Ok(event) => out.push(event),
            Err(RecvTimeoutError::Timeout) => return Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(CaptureError::SessionLost(
                    "the macOS event tap thread stopped".to_owned(),
                ));
            }
        }

        while let Ok(event) = self.events.try_recv() {
            out.push(event);
        }
        Ok(())
    }

    fn set_suppressed(&mut self, suppressed: bool) -> Result<(), CaptureError> {
        self.suppressed.store(suppressed, Ordering::Relaxed);
        super::cursor::hold(suppressed);

        tracing::debug!(suppressed, "local input suppression changed");
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "macos-eventtap"
    }
}

impl Drop for MacOsCapture {
    fn drop(&mut self) {
        // A tap left swallowing input after the process forgets about it would
        // leave the user unable to type at all, which is worse than the stuck
        // key this project is about.
        //
        // Both flags, and in this order: clearing suppression means the very
        // next event passes through even if the run loop takes a moment to
        // notice the shutdown.
        //
        // The cursor is released first of all. A hidden or dissociated pointer
        // that outlives the process is a worse failure than a swallowed event,
        // because nothing the user can do brings it back short of a reboot.
        super::cursor::hold(false);
        self.suppressed.store(false, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// The events the tap asks for.
const fn event_mask() -> u64 {
    1 << CGEventType::KeyDown.0
        | 1 << CGEventType::KeyUp.0
        | 1 << CGEventType::FlagsChanged.0
        | 1 << CGEventType::MouseMoved.0
        | 1 << CGEventType::LeftMouseDown.0
        | 1 << CGEventType::LeftMouseUp.0
        | 1 << CGEventType::RightMouseDown.0
        | 1 << CGEventType::RightMouseUp.0
        | 1 << CGEventType::OtherMouseDown.0
        | 1 << CGEventType::OtherMouseUp.0
        | 1 << CGEventType::LeftMouseDragged.0
        | 1 << CGEventType::RightMouseDragged.0
        | 1 << CGEventType::OtherMouseDragged.0
        | 1 << CGEventType::ScrollWheel.0
}

/// The tap callback.
///
/// Runs on the run loop thread, and must be fast. macOS disables a tap whose
/// callback exceeds an internal timeout, and a disabled tap stops delivering
/// silently. So this translates and queues, and does nothing else.
///
/// # Safety
///
/// Called by CoreGraphics with a valid event and the context pointer given to
/// `tap_create`.
unsafe extern "C-unwind" fn on_event(
    _proxy: objc2_core_graphics::CGEventTapProxy,
    kind: CGEventType,
    event: core::ptr::NonNull<CGEvent>,
    user_info: *mut c_void,
) -> *mut CGEvent {
    // SAFETY: the pointer is the context allocated by `run_tap` on this same
    // thread, and CoreGraphics passes it back unchanged.
    let Some(Some(context)) = (unsafe { user_info.cast::<Option<TapContext>>().as_ref() }) else {
        return event.as_ptr();
    };

    if context.shutdown.load(Ordering::Relaxed) {
        // The capture has been dropped. Stop swallowing at once and wind the
        // run loop down, so the thread does not outlive its purpose.
        CGEvent::tap_enable(&context.tap, false);
        if let Some(run_loop) = CFRunLoop::current() {
            CFRunLoop::stop(&run_loop);
        }
        return event.as_ptr();
    }

    // Our own injection coming back around. Checked before anything else, so
    // the cheapest path through the callback is the one taken most often while
    // this machine is receiving input.
    //
    // SAFETY: CoreGraphics guarantees the event is valid for this call.
    if unsafe { is_ours(event.as_ref()) } {
        return event.as_ptr();
    }

    // A tap the system disabled for taking too long, or because of user input.
    // Re-enabling is the documented recovery, and without it capture stops
    // silently and never resumes.
    if matches!(
        kind,
        CGEventType::TapDisabledByTimeout | CGEventType::TapDisabledByUserInput
    ) {
        tracing::warn!(?kind, "macOS disabled the event tap, re-enabling it");
        CGEvent::tap_enable(&context.tap, true);
        return event.as_ptr();
    }

    // SAFETY: CoreGraphics guarantees the event is valid for this call.
    let translated = translate(kind, unsafe { event.as_ref() });

    if let Some(input) = translated {
        // try_send rather than send. Blocking here would stall the run loop and
        // get the tap disabled, which is worse than dropping one sample.
        //
        // The asymmetry with the X11 backend is deliberate, and worth naming
        // because it weakens a guarantee this project makes loudly. There, a
        // transition blocks rather than being dropped, since losing one
        // desynchronises the receiver's held set. That option does not exist
        // inside a tap callback, so a dropped transition is left to layer 2,
        // the sender's hundred millisecond snapshot, to reconcile. The window
        // between the two is real, so it is logged rather than swallowed.
        if let Err(TrySendError::Full(dropped)) = context.sender.try_send(input)
            && dropped.is_transition()
        {
            tracing::warn!(
                ?dropped,
                "dropped a key transition because the consumer is behind, so the \
                 held set is desynchronised until the next snapshot reconciles it"
            );
        }
    }

    if context.suppressed.load(Ordering::Relaxed) {
        // Swallowed. This is what makes it a KVM rather than a logger.
        return core::ptr::null_mut();
    }
    event.as_ptr()
}

/// Whether this event is one Wraith injected.
///
/// The stamp is set by [`super::inject`] on every event it posts. An event from
/// a real keyboard, or from another application, carries zero here.
fn is_ours(event: &CGEvent) -> bool {
    CGEvent::integer_value_field(Some(event), CGEventField::EventSourceUserData) == OUR_EVENTS
}

/// A CoreGraphics event as a Wraith one.
fn translate(kind: CGEventType, event: &CGEvent) -> Option<InputEvent> {
    match kind {
        CGEventType::KeyDown => key(event, KeyState::Pressed),
        CGEventType::KeyUp => key(event, KeyState::Released),

        // Modifiers arrive as a flags change rather than a key event, and
        // whether it is a press or a release has to be worked out from the
        // flags. Handled in `modifier`.
        CGEventType::FlagsChanged => modifier(event),

        CGEventType::MouseMoved
        | CGEventType::LeftMouseDragged
        | CGEventType::RightMouseDragged
        | CGEventType::OtherMouseDragged => motion(event),

        CGEventType::LeftMouseDown => button(Button::Left, KeyState::Pressed),
        CGEventType::LeftMouseUp => button(Button::Left, KeyState::Released),
        CGEventType::RightMouseDown => button(Button::Right, KeyState::Pressed),
        CGEventType::RightMouseUp => button(Button::Right, KeyState::Released),
        CGEventType::OtherMouseDown => other_button(event, KeyState::Pressed),
        CGEventType::OtherMouseUp => other_button(event, KeyState::Released),

        CGEventType::ScrollWheel => scroll(event),
        _ => None,
    }
}

fn key(event: &CGEvent, state: KeyState) -> Option<InputEvent> {
    let raw = CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode);
    let code = codes::to_evdev(u16::try_from(raw).ok()?)?;

    Some(InputEvent::Key { code, state })
}

/// A modifier change as a press or release.
///
/// macOS reports modifiers through `FlagsChanged` with no direction, so the
/// direction comes from whether the modifier's own flag is now set. Getting
/// this backwards would hold Shift down permanently, which is the exact failure
/// this project exists to prevent.
fn modifier(event: &CGEvent) -> Option<InputEvent> {
    let raw = CGEvent::integer_value_field(Some(event), CGEventField::KeyboardEventKeycode);
    let key = u16::try_from(raw).ok()?;
    let code = codes::to_evdev(key)?;

    let flags = CGEvent::flags(Some(event)).0;
    let state = if flags & flag_for(code) == 0 {
        KeyState::Released
    } else {
        KeyState::Pressed
    };

    Some(InputEvent::Key { code, state })
}

/// The `CGEventFlags` bit a modifier sets while it is held.
const fn flag_for(code: Scancode) -> u64 {
    match code.0 {
        42 | 54 => 0x0002_0000,   // shift
        29 | 97 => 0x0004_0000,   // control
        56 | 100 => 0x0008_0000,  // option
        125 | 126 => 0x0010_0000, // command
        58 => 0x0001_0000,        // caps lock
        _ => 0,
    }
}

fn motion(event: &CGEvent) -> Option<InputEvent> {
    // The delta fields, not the position. These are the unaccelerated values,
    // which is what the far machine wants so it can apply its own curve rather
    // than inheriting ours on top of its own.
    let dx = CGEvent::integer_value_field(Some(event), CGEventField::MouseEventDeltaX);
    let dy = CGEvent::integer_value_field(Some(event), CGEventField::MouseEventDeltaY);

    if dx == 0 && dy == 0 {
        return None;
    }

    Some(InputEvent::MotionRel {
        dx_milli: i32::try_from(dx).unwrap_or(0).saturating_mul(1_000),
        dy_milli: i32::try_from(dy).unwrap_or(0).saturating_mul(1_000),
    })
}

// One arm of the dispatch in `translate`, where the sibling arms genuinely do
// return None: motion drops a zero delta. Unwrapping this one alone would move
// the Some to every call site to save it here.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform with the other arms of one match"
)]
const fn button(button: Button, state: KeyState) -> Option<InputEvent> {
    Some(InputEvent::Button { button, state })
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform with the other arms of one match"
)]
fn other_button(event: &CGEvent, state: KeyState) -> Option<InputEvent> {
    let number = CGEvent::integer_value_field(Some(event), CGEventField::MouseEventButtonNumber);

    let which = match number {
        2 => Button::Middle,
        3 => Button::Back,
        4 => Button::Forward,
        other => Button::Other(u8::try_from(other).unwrap_or(0)),
    };
    Some(InputEvent::Button {
        button: which,
        state,
    })
}

fn scroll(event: &CGEvent) -> Option<InputEvent> {
    let vertical =
        CGEvent::integer_value_field(Some(event), CGEventField::ScrollWheelEventDeltaAxis1);
    let horizontal =
        CGEvent::integer_value_field(Some(event), CGEventField::ScrollWheelEventDeltaAxis2);

    if vertical == 0 && horizontal == 0 {
        return None;
    }

    // Line units to value120, matching the wire format where 120 is one detent.
    Some(InputEvent::Scroll {
        h_v120: i32::try_from(horizontal).unwrap_or(0).saturating_mul(120),
        v_v120: i32::try_from(vertical).unwrap_or(0).saturating_mul(120),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stamp_is_not_a_value_an_ordinary_event_carries() {
        // An untagged event reads zero on this field, so a zero stamp would
        // make Wraith ignore every real keystroke.
        assert_ne!(OUR_EVENTS, 0);
    }

    #[test]
    fn every_modifier_has_a_flag() {
        // A modifier with no flag would read as released the instant it was
        // pressed, or held forever. Both are the failure this project exists
        // to prevent.
        for &code in crate::domain::input::MODIFIER_SCANCODES {
            assert_ne!(flag_for(code), 0, "{code:?} has no CGEventFlags bit");
        }
    }

    #[test]
    fn the_paired_modifiers_share_a_flag() {
        // macOS has one flag per modifier, not per key, so left and right must
        // map to the same bit.
        assert_eq!(flag_for(Scancode(42)), flag_for(Scancode(54)), "shift");
        assert_eq!(flag_for(Scancode(29)), flag_for(Scancode(97)), "control");
        assert_eq!(flag_for(Scancode(56)), flag_for(Scancode(100)), "option");
        assert_eq!(flag_for(Scancode(125)), flag_for(Scancode(126)), "command");
    }

    #[test]
    fn the_modifier_flags_are_distinct() {
        // Sharing a bit would make one modifier's release look like another's.
        let flags = [
            flag_for(Scancode(42)),
            flag_for(Scancode(29)),
            flag_for(Scancode(56)),
            flag_for(Scancode(125)),
        ];

        let mut unique = flags;
        unique.sort_unstable();
        let before = unique.len();
        let deduped: Vec<u64> = {
            let mut v = unique.to_vec();
            v.dedup();
            v
        };

        assert_eq!(
            deduped.len(),
            before,
            "two modifiers share a flag: {flags:?}"
        );
    }

    #[test]
    fn a_non_modifier_has_no_flag() {
        assert_eq!(flag_for(Scancode(30)), 0, "A is not a modifier");
    }

    #[test]
    fn the_event_mask_covers_both_key_directions() {
        // Asking for presses and not releases is how a key gets stuck.
        let mask = event_mask();

        assert_ne!(mask & (1 << CGEventType::KeyDown.0), 0);
        assert_ne!(mask & (1 << CGEventType::KeyUp.0), 0);
        assert_ne!(
            mask & (1 << CGEventType::FlagsChanged.0),
            0,
            "modifiers arrive here"
        );
    }

    #[test]
    fn the_event_mask_covers_dragging() {
        // A drag reports motion under a different event type, and missing it
        // freezes the pointer whenever a button is held.
        let mask = event_mask();

        assert_ne!(mask & (1 << CGEventType::LeftMouseDragged.0), 0);
        assert_ne!(mask & (1 << CGEventType::RightMouseDragged.0), 0);
    }
}
