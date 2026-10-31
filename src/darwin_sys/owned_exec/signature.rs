//! Fixed token-guest + exact cdhash requirement, never PID-guest authority.
use super::*;
use std::{
    ffi::{c_char, c_void},
    ptr::{self, NonNull},
};
type Cf = *const c_void;
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Cf);
    fn CFDataCreate(allocator: Cf, bytes: *const u8, len: isize) -> Cf;
    fn CFStringCreateWithCString(allocator: Cf, bytes: *const c_char, encoding: u32) -> Cf;
    fn CFDictionaryCreate(
        allocator: Cf,
        keys: *const Cf,
        values: *const Cf,
        len: isize,
        key_callbacks: Cf,
        value_callbacks: Cf,
    ) -> Cf;
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: Cf;
    fn SecRequirementCreateWithString(text: Cf, flags: u32, out: *mut Cf) -> i32;
    fn SecCodeCopyGuestWithAttributes(host: Cf, attributes: Cf, flags: u32, out: *mut Cf) -> i32;
    fn SecCodeCheckValidity(code: Cf, flags: u32, requirement: Cf) -> i32;
}
struct OwnedCf(NonNull<c_void>);
impl OwnedCf {
    fn new(value: Cf) -> Result<Self, ExecError> {
        NonNull::new(value.cast_mut()).map(Self).ok_or(ExecError::Allocation)
    }
    fn ptr(&self) -> Cf {
        self.0.as_ptr()
    }
}
impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: one owned Create/Copy reference, never released elsewhere.
        unsafe {
            CFRelease(self.ptr());
        }
    }
}
#[allow(deprecated)] // Locked libc's fixed Mach self-task wrapper; no new dependency.
fn self_audit() -> Result<[u32; 8], ExecError> {
    const TASK_AUDIT_TOKEN: u32 = 15;
    let mut words = [0u32; 8];
    let mut count = 8u32;
    // SAFETY: fixed read of our own task, initialized writable exactly-eight-word output.
    // The kernel count is checked before using any word; no token is logged or exported.
    let rc = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            TASK_AUDIT_TOKEN,
            words.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if rc != 0 || count != 8 || words[5] != std::process::id() {
        return Err(ExecError::Identity);
    }
    Ok(words)
}
pub(super) fn verify(initial: &ProcessInfo, expected: &ExpectedCdHash) -> Result<(), ExecError> {
    let token = child_token(&self_audit()?, initial)?;
    // SAFETY: exact32 bytes initialized from checked owned-child/self kernel observations;
    // CFData copies them before return, never stores this stack pointer.
    let data = OwnedCf::new(unsafe { CFDataCreate(ptr::null(), token.as_ptr().cast(), 32) })?;
    // SAFETY: immutable framework constant, not a caller-selected attribute.
    let key = unsafe { kSecGuestAttributeAudit };
    let value = data.ptr();
    // Null callbacks mean no retains/releases: the immutable key is static, and data remains
    // alive longer than attributes and every synchronous Security call using the dictionary.
    // SAFETY: one valid key/value pointer each; fixed count1, no raw-pointer escape.
    let attributes =
        OwnedCf::new(unsafe { CFDictionaryCreate(ptr::null(), &key, &value, 1, ptr::null(), ptr::null()) })?;
    let mut guest = ptr::null();
    // SAFETY: live dictionary; writable out-ref. Only the token attribute, never PID fallback.
    let rc = unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attributes.ptr(), 0, &mut guest) };
    let guest = NonNull::new(guest.cast_mut()).map(OwnedCf);
    if rc != 0 {
        return Err(ExecError::Security(rc));
    }
    let guest = guest.ok_or(ExecError::Allocation)?;
    let mut text = String::from("cdhash H\"");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in expected.0 {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text.push('"');
    let text = std::ffi::CString::new(text).map_err(|_| ExecError::InvalidSpec)?;
    // SAFETY: bounded generated requirement grammar, valid C string; fixed UTF8 encoding.
    let text = OwnedCf::new(unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), 0x08000100) })?;
    let mut requirement = ptr::null();
    // SAFETY: live generated string, default flags, writable owned out-reference.
    let rc = unsafe { SecRequirementCreateWithString(text.ptr(), 0, &mut requirement) };
    let requirement = NonNull::new(requirement.cast_mut()).map(OwnedCf);
    if rc != 0 {
        return Err(ExecError::Security(rc));
    }
    let requirement = requirement.ok_or(ExecError::Allocation)?;
    // SAFETY: both refs remain owned/live for the synchronous validity call. Exactly0 is
    // success; errors (including stale token/image) are never interpreted as partial trust.
    let rc = unsafe { SecCodeCheckValidity(guest.ptr(), 0, requirement.ptr()) };
    if rc == 0 { Ok(()) } else { Err(ExecError::Security(rc)) }
}
