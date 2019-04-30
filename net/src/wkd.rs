//! OpenPGP Web Key Directory client[draft-koch]
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/

// Hash implements the traits for Sha1
// Sha1 is not used for cryptographic purposes, but for string readability.
use nettle::{
    Hash, hash::insecure_do_not_use::Sha1,
};

use super::{Result};


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

    // After z-base-32 encoding 20 bytes, it should be 30 bytes lenght
    // Even if zbase32 documentation talks about bites, it refers to bytes.
    // encode_full_bytes(data: &[u8]) -> String
    let local_encoded = zbase32::encode_full_bytes(&local_hash[..]);
    // println!("Local part encoded: {:?}", local_encoded);
    local_encoded
}


/// Returns the domain and local_part of an email address
fn split_email_address(email_address: &str) -> Result<(String, String)> {
    // Ensure that is a valid email address by parsing it.
    rfc2822::AddrSpec::parse(email_address)?;
    // print!("addr_spec {:?}", addr_spec);
    let v: Vec<&str> = email_address.split('@').collect();
    let local_part = &v[0].to_lowercase();
    // println!("Local parth: {:?}", local_part);
    let domain = &v[1].to_lowercase();
    // println!("Domain: {:?}", domain);
    Ok((domain.to_string(), local_part.to_string()))
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
        let (domain, local_part) = split_email_address("test1@example.com").
            unwrap();
        assert_eq!(expected_domain, domain);
        assert_eq!(expected_local_part, local_part);
        assert!(split_email_address("thisisnotanemailaddress").is_err());
    }
}
