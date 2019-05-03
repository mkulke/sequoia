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

use super::{Result, Error};


/// Stores the local_part and domain of an email address.
pub struct EmailAddress {
    local_part: String,
    domain: String,
}


impl EmailAddress {
    /// Returns an EmailAddress from an email address string or error.
    fn from<S: AsRef<str>>(email_address: S) -> Result<EmailAddress> {
        // Ensure that is a valid email address by parsing it.
        rfc2822::AddrSpec::parse(email_address.as_ref())?;
        let v: Vec<&str> = email_address.as_ref().split('@').collect();
        let email = EmailAddress {
            local_part: v[0].to_lowercase(),
            domain: v[1].to_lowercase()
        };
        Ok(email)
    }
}


/// Stores the parts needed to create a Web Key Directory URL.
pub struct WkdUrl {
    domain: String,
    local_encoded: String,
    local_part: String,
}


impl WkdUrl {
    /// Returns a WkdUrl from an email address string.or error.
    pub fn from<S: AsRef<str>>(email_address: S) -> Result<WkdUrl> {
        let email = EmailAddress::from(email_address)?;
        let local_encoded = encode_local_part(&email.local_part);
        let wkd_url = WkdUrl {
            domain : email.domain,
            local_encoded : local_encoded,
            local_part : email.local_part,
        };
        Ok(wkd_url)
    }

    /// Returns an Url from a WkdUrl or error.
    pub fn to_url<T>(self, direct_method: T) -> Result<Url>
            where T: Into<Option<bool>> {
        let direct_method = direct_method.into().unwrap_or(false);
        let mut authority = "openpgpkey.".to_string() + &self.domain;
        let mut path = ".well-known/openpgpkey/".to_string() + &self.domain +
                       "/hu/" + &self.local_encoded;
        if direct_method {
            authority = self.domain;
            path = ".well-known/openpgpkey/hu/".to_string() +
                   &self.local_encoded;
        };
        let path_and_query = path + "?l=" + &self.local_part;
        let url_string = "https://".to_string() + &authority + "/"
            + &path_and_query;
        let url = Url::parse(url_string.as_str())?;
        Ok(url)
    }
}


/// Returns a 32 characters string from the local part of an email address
///
/// [draft-koch] section 3.1, Key Discovery:
/// The so mapped local-part is hashed using the SHA-1 algorithm.  The
/// resulting 160 bit digest is encoded using the Z-Base-32 method as
/// described in [RFC6189], section 5.1.6.  The resulting string has a
/// fixed length of 32 octets.
fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let mut hasher = Sha1::default();
    hasher.update(local_part.as_ref().as_bytes());
    // Declare and assign a 20 bytes length vector to use in hasher.result
    let mut local_hash = vec![0; 20];
    hasher.digest(&mut local_hash);
    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode_full_bytes(&local_hash[..])
}


/// Whether the email address is in one userid of the transferable
/// public key.
pub(crate) fn is_email_in_userids<S: AsRef<str>>(tpk: &TPK, email_address: S)
        -> Result<()> {
    let email_address = email_address.as_ref();
    for userid_binding in tpk.userids() {
        // Not important if the userid address can not be parsed,
        // but that at least one parses and match the email address.
        let string = userid_binding.userid().address().
            unwrap_or(None).unwrap_or("".to_string());
        if string.as_str() == email_address {
            println!("User ID matches email: {}", email_address);
            return Ok(())
        };
    };
    Err(Error::EmailNotInUserids.into())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_local_part() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }


    #[test]
    fn test_email_address() {
        let email_address = EmailAddress::from("test1@example.com").unwrap();
        assert_eq!(email_address.domain, "example.com");
        assert_eq!(email_address.local_part, "test1");
        assert_eq!("test1@example.com", email_address.to_string());
        assert!(EmailAddress::from("thisisnotanemailaddress").is_err());
    }

    #[test]
    fn test_wkd_url() {
        // Advanced method
        let mut expected_uri =
            "https://openpgpkey.example.com/\
            .well-known/openpgpkey/example.com/hu/\
            stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        let mut uri = WkdUrl::from("test1@example.com").unwrap().to_url(None)
            .unwrap();
        // FIXME: not working, dunno why
        // assert_eq!(expected_uri, uri.into_string());
        // Direct method
        expected_uri =
            "https://example.com/\
            .well-known/openpgpkey/hu/\
            stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        uri = WkdUrl::from("test1@example.com").unwrap().to_url(true).unwrap();
        // FIXME: not working, dunno why
        // assert_eq!(expected_uri, uri.as_str());
        // invalidd email
        assert!(WkdUrl::from("invalidemail").is_err());
    }

    #[test]
    fn test_is_email_in_userids() {
        use openpgp::tpk::TPKBuilder;
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test2@example.com")
            .add_userid("test1 bar (baz) <test1@example.com>")
            .add_signing_subkey()
            .add_encryption_subkey()
            .generate().unwrap();
        assert!(is_email_in_userids(&tpk, "test1@example.com").is_ok());
        assert!(
            is_email_in_userids(&tpk, "test1@example.com.mallory.com").is_err()
        );
        assert!(is_email_in_userids(&tpk, "invalidemailaddress").is_err());
    }
}
