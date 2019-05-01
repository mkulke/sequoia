//! OpenPGP Web Key Directory client[draft-koch]
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/

// Hash implements the traits for Sha1
// Sha1 is not used for cryptographic purposes, but for string readability.
use nettle::{
    Hash, hash::insecure_do_not_use::Sha1,
};
use url::Url;

use openpgp::TPK;

use super::{Result};


/// # CONSTANTS
static SCHEME: &str = "https";
static WELL_KNOWN: &str = ".well-known";
static OPENPGPKEY : &str = "openpgpkey";
static HU: &str = "hu";
static L: &str = "l";


/// Returns a 32-char long string from the local part of an email address
/// [draft-koch] section 3.1, Key Discovery:
///
/// The so mapped local-part is hashed using the SHA-1 algorithm.  The
/// resulting 160 bit digest is encoded using the Z-Base-32 method as
/// described in [RFC6189], section 5.1.6.  The resulting string has a
/// fixed length of 32 octets.
fn encode_local_part(local_part: &str) -> String {
    let mut hasher = Sha1::default();
    hasher.update(local_part.as_bytes());
    // Declare and assign a 20 bytes length vector to use in hasher.result
    let mut local_hash = vec![0; 20];
    hasher.digest(&mut local_hash);
    // println!("Hash: {:?}", local_hash);

    // After z-base-32 encoding 20 bytes, it should be 30 bytes length
    // Even if zbase32 documentation talks about bites, it refers to bytes.
    // encode_full_bytes(data: &[u8]) -> String
    let local_encoded = zbase32::encode_full_bytes(&local_hash[..]);
    // println!("Local part encoded: {:?}", local_encoded);
    local_encoded
}


/// Returns the local_part and domain of an email address
fn split_email_address(email_address: &str) -> Result<(String, String)> {
    // Ensure that is a valid email address by parsing it.
    rfc2822::AddrSpec::parse(email_address)?;
    // print!("addr_spec {:?}", addr_spec);
    let v: Vec<&str> = email_address.split('@').collect();
    let local_part = &v[0].to_lowercase();
    // println!("Local parth: {:?}", local_part);
    let domain = &v[1].to_lowercase();
    // println!("Domain: {:?}", domain);
    Ok((local_part.to_string(), domain.to_string()))
}


/// Returns the Web Key Directory URL to query.
///
/// # Example advanced direct method:
/// https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/
/// iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe
///
/// # Example direct method:
/// https://example.org/.well-known/openpgpkey/hu/
/// iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe
pub fn create_wkd_url_from_email<T>(email_address: &str, direct_method: T)
            -> Result<Url>
        where T: Into<Option<bool>> {
    let (local_part_string, domain_string) =
        split_email_address(email_address)?;
    let domain = domain_string.as_str();
    let local_part = local_part_string.as_str();
    let local_encoded_string = encode_local_part(&local_part_string);
    let local_encoded = local_encoded_string.as_str();

    let direct_method = direct_method.into().unwrap_or(false);
    let mut authority = [OPENPGPKEY, ".", domain].concat();
    let mut path = vec![WELL_KNOWN, OPENPGPKEY, domain, HU, local_encoded].
        join("/");
    // println!("{:?}", path);
    if direct_method {
        authority = domain.to_string();
        path = vec![WELL_KNOWN, OPENPGPKEY, HU, local_encoded].join("/");
    };

    let path_and_query = [path.as_str(), "?", L, "=", local_part].concat();
    // println!("{:?}", path_and_query);
    // Uri::builder() interprets the first "." in the path as part of the
    // scheme.
    // Url::parse ensure that the URL parses correctly.
    let url = Url::parse(
        [SCHEME, "://", authority.as_str(), "/", path_and_query.as_str()]
        .concat().as_str()
    )?;
    Ok(url)
}


/// Return true if the email address is in one userid of the transferable
/// public.
pub fn is_email_in_userids(tpk: &TPK, email: String) -> bool {
    for userid_binding in tpk.userids() {
        // Not important if the userid address can not be parsed,
        // but that at least one parses and match the email address.
        let string = userid_binding.userid().address().
            unwrap_or(None).unwrap_or("".to_string());
        if string.as_str().contains(email.as_str()) {
            println!("User ID matches email: {}", email);
            return true
        };
    };
    // Create an error type here?
    let msg = format!("Can not find a User ID that matches the email
                      for key: {:?}", tpk.fingerprint());
    eprintln!("{}", msg);
    false
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_local_part() {
        let local_part = "test1";
        let expected_encoded_part = "stnkabub89rpcphiz4ppbxixkwyt1pic";
        let encoded_part = encode_local_part(local_part);
        assert_eq!(expected_encoded_part, encoded_part);
        assert_eq!(32, encoded_part.len());
    }


    #[test]
    fn test_split_email_address() {
        let expected_domain = "example.com";
        let expected_local_part = "test1";
        let (local_part, domain) = split_email_address("test1@example.com").
            unwrap();
        assert_eq!(expected_domain, domain);
        assert_eq!(expected_local_part, local_part);
        assert!(split_email_address("thisisnotanemailaddress").is_err());
    }


    #[test]
    fn test_create_wkd_url_from_email() {
        // Advanced method
        let mut expected_uri = Url::parse(
            "https://openpgpkey.example.com/\
            .well-known/openpgpkey/example.com/hu/\
            stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1").unwrap();
        let mut uri = create_wkd_url_from_email("test1@example.com", None).unwrap();
        assert_eq!(expected_uri, uri);
        // Direct method
        expected_uri = Url::parse(
            "https://example.com/\
            .well-known/openpgpkey/hu/\
            stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1").unwrap();
        uri = create_wkd_url_from_email("test1@example.com", true).unwrap();
        assert_eq!(expected_uri, uri);
        // invalidd email
        assert!(create_wkd_url_from_email("invalidemail", true).is_err());
    }

    #[test]
    fn test_is_email_in_userids() {
        // tpk: &TPK, email: String) -> bool
    }
}
