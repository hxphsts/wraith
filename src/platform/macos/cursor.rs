//! The pointer, while the cursor is on another machine.
//!
//! Shared between the tap and the injector rather than owned by either, because
//! both ends of a crossing have to touch it and they touch it at different
//! moments. Suppression is a capture concern and the warp is an injection one,
//! but the pointer is one pointer.
//!
//! # Why the injector releases it rather than waiting to be told
//!
//! Suppression travels as a flag that the capture thread reads at the top of a
//! loop it spends fifty milliseconds inside. That is fine for suppression, which
//! nobody can perceive being a frame late. It is not fine for the pointer: for
//! those fifty milliseconds the cursor is still frozen and hidden while the
//! hand is already moving it, which is felt as the pointer stopping dead on
//! arrival. So the warp releases it directly, and the flag arriving later finds
//! it already done.

use std::sync::atomic::{AtomicBool, Ordering};

use objc2_core_graphics::{
    CGAssociateMouseAndMouseCursorPosition, CGDisplayHideCursor, CGDisplayShowCursor, CGError,
    CGMainDisplayID,
};

/// Freezes and hides the pointer, or gives it back.
///
/// While the cursor is on another machine this one's pointer must not move.
/// Dissociating is how a macOS game takes the mouse: the sprite stops dead and
/// the events keep arriving carrying deltas, which is exactly what a KVM wants
/// and is why the older approach of warping the pointer back to the centre on
/// every motion is being abandoned everywhere. There is no warp, so there is no
/// warp echo to recognise and discard.
///
/// Hiding needs [`allow_background`] to have run, or it does nothing at
/// all for a process that is not frontmost.
///
/// Idempotent, and it has to be: `CGDisplayHideCursor` and `CGDisplayShowCursor`
/// are reference counted, so two hides and one show leave a cursor that nothing
/// short of a reboot brings back. The caller two layers up happens to
/// deduplicate today, which is not a property worth depending on from here.
pub fn hold(held: bool) {
    static HELD: AtomicBool = AtomicBool::new(false);

    if HELD.swap(held, Ordering::Relaxed) == held {
        return;
    }

    let display = CGMainDisplayID();

    let status = if held {
        allow_background();

        let hidden = CGDisplayHideCursor(display);
        if hidden != CGError::Success {
            tracing::warn!(status = ?hidden, "cannot hide the pointer");
        }

        CGAssociateMouseAndMouseCursorPosition(false)
    } else {
        // Association first: `CGDisplayShowCursor` re-associates as a side
        // effect on some releases, and relying on that would make the order
        // load bearing for a reason nothing here states.
        let associated = CGAssociateMouseAndMouseCursorPosition(true);
        let _ = CGDisplayShowCursor(display);
        associated
    };

    if status != CGError::Success {
        // Worth saying loudly in the release direction: a pointer left
        // dissociated does not respond to the mouse at all.
        tracing::warn!(held, ?status, "cannot change the pointer association");
    }
}

/// Tells the window server this process may hide the cursor from the background.
///
/// `CGDisplayHideCursor` is ignored for a process that is not frontmost, and a
/// daemon never is, so without this the pointer freezes where it stands and
/// stays drawn. The switch is a private CoreGraphics connection property. Every
/// shipping software KVM on this platform sets it and Apple publishes no
/// equivalent, so the choice is this or a visible cursor.
///
/// Resolved at runtime rather than linked, deliberately. If either symbol is
/// ever withdrawn the worst case is the cursor staying visible, which is the
/// behaviour without any of this, rather than a daemon that will not launch.
///
/// Known hole: the cursor reappears over the Dock, which the window server
/// enforces so that the Dock always keeps cursor control. It matters little
/// here, since the pointer is frozen and can only be over the Dock if it was
/// parked there when the cursor left.
pub fn allow_background() {
    static ONCE: std::sync::Once = std::sync::Once::new();

    ONCE.call_once(|| {
        let Some((connection, set)) = window_server_property() else {
            return;
        };

        // SAFETY: a NUL terminated ASCII literal, and the default allocator.
        let key = unsafe {
            cgs::CFStringCreateWithCString(
                std::ptr::null(),
                c"SetsCursorInBackground".as_ptr(),
                cgs::UTF8,
            )
        };

        if key.is_null() {
            return;
        }

        // SAFETY: the connection id is whatever the window server handed back,
        // the key was just created, and the value is a CoreFoundation constant.
        // The key is released afterwards because the property retains its own.
        unsafe {
            let id = connection();
            let status = set(id, id, key, cgs::kCFBooleanTrue);

            cgs::CFRelease(key);

            if status == 0 {
                tracing::debug!("the pointer can be hidden from the background");
            } else {
                tracing::warn!(status, "cannot ask to hide the pointer from the background");
            }
        }
    });
}

/// Looks up the two private window server entry points, or explains their absence.
///
/// `None` on any macOS that does not export them, which costs the pointer
/// staying visible while the cursor is away and nothing else. A daemon that
/// refused to start over a cosmetic detail would be the worse failure.
fn window_server_property() -> Option<(cgs::DefaultConnection, cgs::SetProperty)> {
    // SAFETY: a NUL terminated literal path. A framework that is not there
    // comes back null, which is checked before it is used.
    let library = unsafe { cgs::dlopen(cgs::CORE_GRAPHICS.as_ptr(), cgs::RTLD_LAZY) };

    if library.is_null() {
        tracing::info!("no CoreGraphics to ask, so the pointer will stay visible");
        return None;
    }

    // SAFETY: the handle came from `dlopen` and both names are NUL terminated
    // literals. A missing symbol comes back null, which is checked before
    // anything is called through it.
    let (connection, set) = unsafe {
        (
            cgs::dlsym(library, c"_CGSDefaultConnection".as_ptr()),
            cgs::dlsym(library, c"CGSSetConnectionProperty".as_ptr()),
        )
    };

    if connection.is_null() || set.is_null() {
        tracing::info!(
            "this macOS has no CGSSetConnectionProperty, so the pointer will \
             freeze while the cursor is away but stay visible"
        );
        return None;
    }

    // SAFETY: both pointers are non-null, and the signatures are the ones these
    // two symbols have carried since Mac OS X 10.2. A wrong signature here would
    // be a memory error, which is why they are written out rather than
    // transmuted from something more convenient.
    unsafe {
        Some((
            std::mem::transmute::<*mut std::ffi::c_void, cgs::DefaultConnection>(connection),
            std::mem::transmute::<*mut std::ffi::c_void, cgs::SetProperty>(set),
        ))
    }
}

/// The window server entry points that have no public header.
///
/// Gathered here rather than inside the one function that calls them, which put
/// four `extern` blocks and two type aliases in the middle of the logic they
/// support and took it well past the length limit.
mod cgs {
    use std::ffi::c_void;

    /// The framework that re-exports the window server's `CGS` entry points.
    ///
    /// Opened by path rather than searching every loaded image through
    /// `RTLD_DEFAULT`, which is a platform specific magic value and, given a
    /// wrong one, faults inside `dlsym` instead of returning null. A path that
    /// does not exist is an ordinary null handle, which is the whole point of
    /// doing this at runtime.
    pub const CORE_GRAPHICS: &std::ffi::CStr =
        c"/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics";

    pub const RTLD_LAZY: i32 = 0x1;
    pub const UTF8: u32 = 0x0800_0100;

    pub type DefaultConnection = unsafe extern "C" fn() -> i32;
    pub type SetProperty = unsafe extern "C" fn(i32, i32, *const c_void, *const c_void) -> i32;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        pub static kCFBooleanTrue: *const c_void;

        pub fn CFStringCreateWithCString(
            allocator: *const c_void,
            bytes: *const std::ffi::c_char,
            encoding: u32,
        ) -> *const c_void;
        pub fn CFRelease(value: *const c_void);
    }

    unsafe extern "C" {
        pub fn dlopen(path: *const std::ffi::c_char, mode: i32) -> *mut c_void;
        pub fn dlsym(handle: *mut c_void, symbol: *const std::ffi::c_char) -> *mut c_void;
    }
}

/// Stops a warp from freezing the mouse for a quarter of a second.
///
/// `CGWarpMouseCursorPosition` leaves macOS ignoring physical mouse movement
/// for a documented interval afterwards, and the default is 0.25 seconds. On
/// arrival that is the hand already moving while the cursor sits still, which
/// is the whole of "the pointer stops when it comes back".
///
/// The global setter rather than the per-source one, deprecated though it is.
/// A warp is not posted through anybody's event source, so scoping the interval
/// to ours would leave the thing that actually needs it untouched. Every
/// software KVM on this platform makes the same call for the same reason.
pub fn stop_freezing_after_warps() {
    static ONCE: std::sync::Once = std::sync::Once::new();

    ONCE.call_once(|| {
        #[expect(
            deprecated,
            reason = "the replacement is scoped to an event source, and a warp belongs to none"
        )]
        let status = objc2_core_graphics::CGSetLocalEventsSuppressionInterval(0.0);

        if status == CGError::Success {
            tracing::debug!("warps will not suppress local input");
        } else {
            tracing::warn!(?status, "a warp may still freeze the pointer briefly");
        }
    });
}
