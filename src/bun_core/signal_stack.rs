//! Per-thread alternate signal stack for the crash handler. A stack overflow
//! faults on the guard page, so the kernel can deliver the signal only onto an
//! alternate stack (`SA_ONSTACK` handler + `sigaltstack(2)` on the thread).
//! `Output::Source::configure_thread` installs one on every bun thread; the
//! main thread uses the crash handler's static buffer.

use core::cell::Cell;

/// Excludes the guard page below it. The crash handler runs its report on it.
pub const ALT_STACK_SIZE: usize = 512 * 1024;

/// This thread's alternate stack mapping; dropped by the thread-local destructor.
struct Mapping {
    base: *mut libc::c_void,
    len: usize,
}

impl Mapping {
    fn new() -> Option<Mapping> {
        // SAFETY: `sysconf` has no preconditions.
        let page = match usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) {
            Ok(page) if page > 0 => page,
            _ => 4096,
        };
        let len = ALT_STACK_SIZE + page;
        // SAFETY: anonymous private mapping; no file, no fixed address.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return None;
        }
        // Guard page: an overflow of the handler itself faults instead of writing
        // into the mapping below.
        // SAFETY: `base` is page-aligned and the first page belongs to the mapping.
        unsafe { libc::mprotect(base, page, libc::PROT_NONE) };
        Some(Mapping { base, len })
    }

    /// The part above the guard page.
    fn stack(&self) -> libc::stack_t {
        let mut stack: libc::stack_t = crate::ffi::zeroed();
        // SAFETY: the guard page is `len - ALT_STACK_SIZE` bytes of the mapping.
        stack.ss_sp = unsafe { self.base.byte_add(self.len - ALT_STACK_SIZE) };
        stack.ss_size = ALT_STACK_SIZE;
        stack
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let mut disable: libc::stack_t = crate::ffi::zeroed();
        disable.ss_flags = libc::SS_DISABLE;
        // SAFETY: `disable` is a valid `stack_t`; a null `old_ss` is permitted.
        unsafe { libc::sigaltstack(&raw const disable, core::ptr::null_mut()) };
        // SAFETY: `base`/`len` describe the mapping `Mapping::new` created, and
        // the kernel no longer uses it as a signal stack.
        unsafe { libc::munmap(self.base, self.len) };
    }
}

thread_local! {
    static MAPPING: Cell<Option<Mapping>> = const { Cell::new(None) };
}

/// Register an alternate signal stack for the calling thread. No-op when one is
/// already active (main thread, a repeat call, or ASAN's). Failure is silent.
pub fn install_for_current_thread() {
    let mut current: libc::stack_t = crate::ffi::zeroed();
    // SAFETY: a null `ss` only queries; `current` is a valid out-pointer.
    if unsafe { libc::sigaltstack(core::ptr::null(), &raw mut current) } != 0
        || current.ss_flags & libc::SS_DISABLE == 0
    {
        return;
    }

    // `Some` when something disabled the stack this thread registered before.
    let Some(mapping) = MAPPING.with(Cell::take).or_else(Mapping::new) else {
        return;
    };
    let stack = mapping.stack();
    // SAFETY: `stack` describes a live, writable mapping; a null `old_ss` is
    // permitted.
    if unsafe { libc::sigaltstack(&raw const stack, core::ptr::null_mut()) } == 0 {
        MAPPING.with(|slot| slot.set(Some(mapping)));
    }
}
