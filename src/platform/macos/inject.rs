//! macOS injection, through CoreGraphics.
//!
//! # Permissions
//!
//! Posting events needs the Accessibility grant. Wraith checks before every
//! post rather than assuming, because the grant can be revoked while running
//! and the failure mode otherwise is input silently going nowhere.
//!
//! The check is cheap, and "silently does nothing" is the worst possible
//! behaviour for a tool whose entire job is moving input between machines.
//!
//! # Telling our own input apart
//!
//! Every event created here is stamped with [`OUR_EVENTS`] on the
//! `EventSourceUserData` field, so [`super::tap`] can ignore it. Without that
//! stamp a receiving Mac captures its own injection and, with its cursor
//! remote, sends it back to where it came from.
//!
//! # What macOS gives us for free
//!
//! Unlike X11 XTEST, a `CGEventSource` tied to a process does not outlive it: a
//! killed process leaves no keys held. So the residual case that makes
//! `wraith unstick` necessary on X11 does not arise here, and
//! `releases_on_disconnect` says so.

use objc2_core_foundation::{CGPoint, CGRect};
use objc2_core_graphics::{
    CGAssociateMouseAndMouseCursorPosition, CGDisplayBounds, CGError, CGEvent, CGEventField,
    CGEventSource, CGEventSourceStateID, CGEventTapLocation, CGEventType, CGGetActiveDisplayList,
    CGMainDisplayID, CGMouseButton, CGScrollEventUnit, CGWarpMouseCursorPosition,
};

use super::{OUR_EVENTS, codes};
use crate::domain::{Button, InputEvent, KeyState, Point, Scancode};
use crate::ports::inject::{Inject, InjectError};
use crate::ports::screen_info::{LocalScreen, ScreenInfo, ScreenInfoError};

// CoreGraphics functions the bindings do not expose. Declared here rather than
// vendored from a stale crate: each is a stable public C symbol in
// ApplicationServices.
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    /// Whether this process may post events. Does not prompt.
    fn CGPreflightPostEventAccess() -> bool;
    /// Asks for the Accessibility grant, prompting once.
    fn CGRequestPostEventAccess() -> bool;
}

/// The rectangle every display on this machine sits inside, in points.
///
/// Quartz puts the main display's top left at the origin and lets the others
/// sit anywhere around it, so a second monitor above or to the left produces
/// negative coordinates. A machine's pointer therefore moves through the union,
/// not through any one display, and asking `CGMainDisplayID` for the size
/// describes a smaller space than the pointer can reach.
///
/// The domain works in a screen whose origin is zero. The offset between the
/// two is applied at every crossing of this boundary and never leaves this
/// file, which is what keeps a macOS detail out of `LocalScreen`.
///
/// Points rather than backing pixels, because that is the space `CGEvent`
/// locations and `CGWarpMouseCursorPosition` both speak. `CGDisplayPixelsWide`
/// answers a different question and mixing the two halves every coordinate on a
/// Retina display.
#[derive(Clone, Copy, Debug)]
struct Desktop {
    origin_x: f64,
    origin_y: f64,
    width_px: u32,
    height_px: u32,
}

impl Desktop {
    /// Measures the union of the active displays.
    fn read() -> Self {
        // Sixteen displays is past any desk this will run on, and the array is
        // the only bound the call has.
        let mut ids = [0_u32; 16];
        let mut found: u32 = 0;

        // SAFETY: the pointer is valid for the whole array, whose length is
        // what is passed, and the count pointer is a live local.
        let status = unsafe {
            CGGetActiveDisplayList(
                u32::try_from(ids.len()).unwrap_or(0),
                ids.as_mut_ptr(),
                &raw mut found,
            )
        };

        // The main display alone, if the list could not be read. Wrong on a
        // multi-monitor Mac, and better than a screen of no size.
        let fallback = [CGMainDisplayID()];
        let listed = usize::try_from(found).unwrap_or(0);

        let displays = match ids.get(..listed) {
            Some(active) if status == CGError::Success && !active.is_empty() => active,
            _ => {
                tracing::warn!(?status, "cannot list the displays, assuming the main one");
                &fallback
            }
        };

        let bounds: Vec<CGRect> = displays.iter().map(|&id| CGDisplayBounds(id)).collect();

        Self::union(&bounds)
    }

    /// The rectangle containing every one of `bounds`.
    ///
    /// Separate from [`Self::read`] so the arithmetic can be reasoned about
    /// without a window server, which is the only part of this file that can be.
    fn union(bounds: &[CGRect]) -> Self {
        let (mut left, mut top) = (f64::MAX, f64::MAX);
        let (mut right, mut bottom) = (f64::MIN, f64::MIN);

        for rect in bounds {
            left = left.min(rect.origin.x);
            top = top.min(rect.origin.y);
            right = right.max(rect.origin.x + rect.size.width);
            bottom = bottom.max(rect.origin.y + rect.size.height);
        }

        let (width, height) = (right - left, bottom - top);

        Self {
            origin_x: left,
            origin_y: top,
            width_px: if width > 0.0 { span(width) } else { 1_920 },
            height_px: if height > 0.0 { span(height) } else { 1_080 },
        }
    }

    /// A Quartz location as a point on the domain's screen.
    const fn to_local(self, at: CGPoint) -> Point {
        Point::new(whole(at.x - self.origin_x), whole(at.y - self.origin_y))
    }

    /// A point on the domain's screen as a Quartz location.
    fn to_global(self, at: Point) -> CGPoint {
        CGPoint {
            x: f64::from(at.x_px) + self.origin_x,
            y: f64::from(at.y_px) + self.origin_y,
        }
    }
}

/// A Quartz coordinate as a whole pixel.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a fractional point has no representation on a pixel grid"
)]
const fn whole(value: f64) -> i32 {
    value as i32
}

/// A measured span as a pixel count.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a display span is positive and far inside u32"
)]
const fn span(value: f64) -> u32 {
    value as u32
}

/// A `CGEventSource` that may cross threads.
///
/// CoreFoundation objects are not marked `Send` by the bindings, and rightly
/// so in general. This one is safe to move because of how it is used rather
/// than because of what it is, so the reasoning lives here where it can be
/// checked.
struct SendableSource(objc2_core_foundation::CFRetained<CGEventSource>);

// The lint is right that the field is not `Send`. The argument for why the
// wrapper is rests on ownership rather than on the type, and is the SAFETY note
// below, which has to stay directly above the impl or the lint that wants a
// safety comment stops finding it.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "safety rests on exclusive ownership, argued below"
)]
// SAFETY: the source is created once, moved into the injector, and thereafter
// touched only by the injector thread, which owns the whole `MacOsInject`
// exclusively. `Inject` takes `&mut self`, so no two threads can reach it at
// once even if one were somehow shared. CoreGraphics itself permits an event
// source to be used from any single thread; what it forbids is concurrent use,
// which the ownership here already prevents.
unsafe impl Send for SendableSource {}

/// Injects input through CoreGraphics.
pub struct MacOsInject {
    source: SendableSource,
    /// Where the pointer was last put, so relative motion has somewhere to start.
    ///
    /// CoreGraphics has no relative mouse event: every motion is absolute. The
    /// position is tracked here rather than read back before each move, because
    /// reading back costs a round trip on the hottest path in the system.
    cursor: Point,
    desktop: Desktop,
}

impl std::fmt::Debug for MacOsInject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsInject")
            .field("cursor", &self.cursor)
            .field("desktop", &self.desktop)
            .finish_non_exhaustive()
    }
}

impl MacOsInject {
    /// Opens an injector, prompting for Accessibility if it is not granted.
    pub fn open() -> Result<Self, InjectError> {
        // SAFETY: both take no arguments and return a bool. Preflight is asked
        // first so a granted process never sees a prompt.
        let granted = unsafe { CGPreflightPostEventAccess() || CGRequestPostEventAccess() };

        if !granted {
            return Err(InjectError::PermissionDenied(
                "Wraith needs Accessibility to send input. Grant it in System Settings, \
                 Privacy and Security, Accessibility, then start Wraith again"
                    .to_owned(),
            ));
        }

        let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState).ok_or_else(|| {
            InjectError::Backend("cannot create a CoreGraphics event source".to_owned())
        })?;

        let desktop = Desktop::read();

        // Once, and before any warp. Without it every warp is followed by a
        // quarter of a second in which macOS ignores the mouse, which on
        // arrival is the pointer visibly stopping under the hand.
        super::cursor::stop_freezing_after_warps();

        Ok(Self {
            source: SendableSource(source),
            cursor: read_pointer(desktop).unwrap_or_else(|| Point::new(0, 0)),
            desktop,
        })
    }

    /// Whether the Accessibility grant is still in place.
    ///
    /// Checked before each batch. A grant revoked while running turns every
    /// post into a silent no-op, and a tool that silently stops working is
    /// worse than one that says why.
    fn permitted() -> Result<(), InjectError> {
        // SAFETY: takes no arguments, returns a bool, and does not prompt.
        if unsafe { CGPreflightPostEventAccess() } {
            return Ok(());
        }

        Err(InjectError::PermissionDenied(
            "the Accessibility grant was withdrawn, so input cannot be sent".to_owned(),
        ))
    }

    fn emit_key(&self, code: Scancode, state: KeyState) -> Result<(), InjectError> {
        let key = codes::to_macos(code).ok_or_else(|| {
            InjectError::Unrepresentable(format!("evdev {} has no macOS keycode", code.0))
        })?;

        let event =
            CGEvent::new_keyboard_event(Some(&self.source.0), key, state == KeyState::Pressed)
                .ok_or_else(|| InjectError::Backend("cannot create a key event".to_owned()))?;

        post(&event);
        Ok(())
    }

    fn emit_button(&self, button: Button, state: KeyState) -> Result<(), InjectError> {
        let (macos_button, down, up) = match button {
            Button::Left => (
                CGMouseButton::Left,
                CGEventType::LeftMouseDown,
                CGEventType::LeftMouseUp,
            ),
            Button::Right => (
                CGMouseButton::Right,
                CGEventType::RightMouseDown,
                CGEventType::RightMouseUp,
            ),
            // macOS folds every other button into "other", distinguished by the
            // button number field rather than by the event type.
            Button::Middle | Button::Back | Button::Forward | Button::Other(_) => (
                CGMouseButton::Center,
                CGEventType::OtherMouseDown,
                CGEventType::OtherMouseUp,
            ),
        };

        let kind = if state == KeyState::Pressed { down } else { up };
        let event =
            CGEvent::new_mouse_event(Some(&self.source.0), kind, self.cg_point(), macos_button)
                .ok_or_else(|| InjectError::Backend("cannot create a button event".to_owned()))?;

        if let Some(number) = other_button_number(button) {
            CGEvent::set_integer_value_field(
                Some(&event),
                CGEventField::MouseEventButtonNumber,
                number,
            );
        }

        post(&event);
        Ok(())
    }

    fn emit_motion(&mut self, dx_milli: i32, dy_milli: i32) -> Result<(), InjectError> {
        let moved = Point::new(
            (self.cursor.x_px + dx_milli / 1_000).clamp(
                0,
                i32::try_from(self.desktop.width_px.saturating_sub(1)).unwrap_or(i32::MAX),
            ),
            (self.cursor.y_px + dy_milli / 1_000).clamp(
                0,
                i32::try_from(self.desktop.height_px.saturating_sub(1)).unwrap_or(i32::MAX),
            ),
        );

        if moved == self.cursor {
            // Sub-pixel motion. macOS has no sub-pixel cursor position, so
            // posting this would be a wasted event that moves nothing.
            return Ok(());
        }
        self.cursor = moved;

        self.post_move()
    }

    fn post_move(&self) -> Result<(), InjectError> {
        let event = CGEvent::new_mouse_event(
            Some(&self.source.0),
            CGEventType::MouseMoved,
            self.cg_point(),
            CGMouseButton::Left,
        )
        .ok_or_else(|| InjectError::Backend("cannot create a motion event".to_owned()))?;

        post(&event);
        Ok(())
    }

    fn emit_scroll(&self, h_v120: i32, v_v120: i32) -> Result<(), InjectError> {
        // macOS scroll units are lines, and 120 is one detent. Dividing keeps a
        // high-resolution wheel from scrolling a hundred times too far.
        let (horizontal, vertical) = (h_v120 / 120, v_v120 / 120);

        if horizontal == 0 && vertical == 0 {
            return Ok(());
        }

        let event = CGEvent::new_scroll_wheel_event2(
            Some(&self.source.0),
            CGScrollEventUnit::Line,
            2,
            vertical,
            horizontal,
            0,
        )
        .ok_or_else(|| InjectError::Backend("cannot create a scroll event".to_owned()))?;

        post(&event);
        Ok(())
    }

    fn cg_point(&self) -> CGPoint {
        self.desktop.to_global(self.cursor)
    }
}

impl Inject for MacOsInject {
    fn pointer(&self) -> Option<&dyn crate::ports::ScreenInfo> {
        Some(self)
    }

    fn emit(&mut self, events: &[InputEvent]) -> Result<(), InjectError> {
        Self::permitted()?;

        for &event in events {
            let sent = match event {
                InputEvent::Key { code, state } => self.emit_key(code, state),
                InputEvent::Button { button, state } => self.emit_button(button, state),
                InputEvent::MotionRel { dx_milli, dy_milli } => {
                    self.emit_motion(dx_milli, dy_milli)
                }
                InputEvent::Scroll { h_v120, v_v120 } => self.emit_scroll(h_v120, v_v120),
            };

            match sent {
                Ok(()) => {}
                // An unrepresentable event is skipped, not fatal. One exotic key
                // must never abort the rest of a batch, because that batch is
                // often a chord release.
                Err(InjectError::Unrepresentable(what)) => {
                    tracing::debug!(reason = %what, "skipping an event macOS cannot express");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn warp_absolute(&mut self, at: Point) -> Result<(), InjectError> {
        Self::permitted()?;
        self.cursor = at;

        // Before the warp, and not left to the suppression flag that follows it.
        // That flag is read by the capture thread at the top of a loop it
        // spends fifty milliseconds inside, and for those fifty milliseconds
        // the pointer is still frozen and hidden while the hand is already
        // moving it. Idempotent, so the flag arriving later costs nothing.
        super::cursor::hold(false);

        // A real warp, not a posted MouseMoved. A synthetic motion event
        // carries a location but does not move the sprite, so the pointer never
        // arrives where the crossing said and the far machine appears to resume
        // wherever it was last left.
        let status = CGWarpMouseCursorPosition(self.desktop.to_global(at));

        if status != CGError::Success {
            return Err(InjectError::Backend(format!(
                "cannot move the pointer: CoreGraphics returned {status:?}"
            )));
        }

        // Not a no-op, however much it looks like one. macOS ignores physical
        // mouse movement for about a quarter of a second after a warp, which is
        // felt as having to shove the mouse two or three times before the
        // machine you just crossed to responds. Re-associating cancels that
        // interval. Deleting this line brings the dead cursor back, and nothing
        // about the symptom points here.
        let associated = CGAssociateMouseAndMouseCursorPosition(true);

        if associated != CGError::Success {
            tracing::warn!(
                status = ?associated,
                "the pointer stayed dissociated, so input may lag the warp"
            );
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<(), InjectError> {
        // CoreGraphics posts synchronously, so there is nothing buffered.
        Ok(())
    }

    fn releases_on_disconnect(&self) -> bool {
        // Unlike X11 XTEST, a CGEventSource does not outlive its process, so a
        // killed Wraith leaves nothing held.
        true
    }

    fn backend_name(&self) -> &'static str {
        "macos-coregraphics"
    }
}

impl ScreenInfo for MacOsInject {
    fn local_screen(&self) -> Result<LocalScreen, ScreenInfoError> {
        Ok(LocalScreen {
            width_px: self.desktop.width_px,
            height_px: self.desktop.height_px,
        })
    }

    fn cursor_position(&self) -> Result<Point, ScreenInfoError> {
        read_pointer(self.desktop).ok_or_else(|| {
            ScreenInfoError::Backend("cannot read the pointer from CoreGraphics".to_owned())
        })
    }
}

/// Where the pointer actually is.
///
/// A round trip to the window server, and it has to be: the alternative is
/// answering with `self.cursor`, which this injector only ever writes when it
/// injects. While this machine holds its own cursor it injects nothing, so that
/// value freezes at the last warp target, one pixel inside the edge the cursor
/// last arrived through. Fed back through `CursorMachine::resync` twenty times
/// a second, it pins the session against that edge and every motion into it
/// crosses, wherever the visible pointer is.
///
/// `CGEventCreate(NULL)` builds an event carrying the current location without
/// posting anything, which is the documented way to ask.
fn read_pointer(desktop: Desktop) -> Option<Point> {
    CGEvent::new(None).map(|event| desktop.to_local(CGEvent::location(Some(&event))))
}

/// Stamps an event as ours and posts it.
///
/// The stamp is what stops a receiving Mac capturing its own injection and,
/// with its cursor remote, forwarding it back. Every post goes through here so
/// a new event kind cannot be added without one.
fn post(event: &CGEvent) {
    CGEvent::set_integer_value_field(Some(event), CGEventField::EventSourceUserData, OUR_EVENTS);
    CGEvent::post(CGEventTapLocation::HIDEventTap, Some(event));
}

/// The button number macOS wants for anything beyond left and right.
///
/// Middle is 2, and the side buttons continue from there. Left and right carry
/// their identity in the event type instead, so they need no number.
const fn other_button_number(button: Button) -> Option<i64> {
    match button {
        Button::Left | Button::Right => None,
        Button::Middle => Some(2),
        Button::Back => Some(3),
        Button::Forward => Some(4),
        Button::Other(n) => Some(n as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_and_right_carry_no_button_number() {
        // They are distinguished by the event type, and setting a number as
        // well would confuse applications that read it.
        assert_eq!(other_button_number(Button::Left), None);
        assert_eq!(other_button_number(Button::Right), None);
    }

    #[test]
    fn the_other_buttons_are_numbered_from_middle() {
        assert_eq!(other_button_number(Button::Middle), Some(2));
        assert_eq!(other_button_number(Button::Back), Some(3));
        assert_eq!(other_button_number(Button::Forward), Some(4));
    }

    #[test]
    fn no_two_buttons_share_a_number() {
        let numbers: Vec<i64> = [Button::Middle, Button::Back, Button::Forward]
            .into_iter()
            .filter_map(other_button_number)
            .collect();

        let mut unique = numbers.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(
            unique.len(),
            numbers.len(),
            "two buttons would land on the same one"
        );
    }
}

#[cfg(test)]
mod desktop_tests {
    use super::*;
    use objc2_core_foundation::CGSize;

    const fn rect(x: f64, y: f64, width: f64, height: f64) -> CGRect {
        CGRect {
            origin: CGPoint { x, y },
            size: CGSize { width, height },
        }
    }

    #[test]
    fn a_display_left_of_the_main_one_gives_a_negative_origin() {
        // Quartz pins the main display's top left to the origin and lets the
        // others fall where they are placed, so a second monitor to the left
        // puts the union's corner at a negative x. Measuring only the main
        // display describes a space smaller than the pointer can reach.
        let desktop = Desktop::union(&[
            rect(0.0, 0.0, 1512.0, 982.0),
            rect(-1920.0, 0.0, 1920.0, 1080.0),
        ]);

        assert_eq!(desktop.width_px, 3432);
        assert_eq!(desktop.height_px, 1080);

        // The union's far corner is the domain's origin, and the trip back
        // agrees.
        assert_eq!(
            desktop.to_local(CGPoint { x: -1920.0, y: 0.0 }),
            Point::new(0, 0)
        );
        assert!((desktop.to_global(Point::new(0, 0)).x + 1920.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_single_display_needs_no_offset() {
        let desktop = Desktop::union(&[rect(0.0, 0.0, 1512.0, 982.0)]);

        assert_eq!(
            desktop.to_local(CGPoint { x: 700.0, y: 400.0 }),
            Point::new(700, 400)
        );
    }

    #[test]
    fn no_displays_falls_back_rather_than_reporting_a_zero_screen() {
        // A zero width would divide by zero in the layout's entry point.
        let desktop = Desktop::union(&[]);

        assert_eq!((desktop.width_px, desktop.height_px), (1_920, 1_080));
    }
}
