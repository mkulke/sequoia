//! User Attribute packets.
//!
//! See [Section 5.12 of RFC 4880] for details.
//!
//!   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12

use libc::size_t;
use sequoia_openpgp as openpgp;
use super::Packet;

use crate::RefRaw;

/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_user_attribute_value(ua: *const Packet,
                                               value_len: Option<&mut size_t>)
                                               -> *const u8 {
    if let openpgp::Packet::UserAttribute(ref ua) = ua.ref_raw() {
        if let Some(p) = value_len {
            *p = ua.value().len();
        }
        ua.value().as_ptr()
    } else {
        panic!("Not a UserAttribute packet");
    }
}
