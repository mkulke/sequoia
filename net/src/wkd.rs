//! OpenPGP Web Key Directory client[draft-koch]
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service/#section-3.1

// XXX: We might want to merge the 2 structs in the future and move the
// functions to methods.
use hyper::Uri;
// Hash implements the traits for Sha1
// Sha1 is used to obtain a 20 bytes digest that after zbase32 encoding can
// be used as file name
use nettle::{
    Hash, hash::insecure_do_not_use::Sha1,
};
use url::Url;

use openpgp::TPK;
use openpgp::parse::Parse;
use openpgp::tpk::TPKParser;

use super::{Result, Error};


/// Stores the local_part and domain of an email address.
pub struct EmailAddress {
    local_part: String,
    domain: String,
}


impl EmailAddress {
    /// Returns an EmailAddress from an email address string.
    ///
    /// [draft-koch]:
    /// To help with the common pattern of using capitalized names
    /// (e.g.  "Joe.Doe@example.org") for mail addresses, and under the
    /// premise that almost all MTAs treat the local-part case-insensitive
    /// and that the domain-part is required to be compared case-insensitive
    /// anyway, all upper-case ASCII characters in a User ID are mapped to
    /// lowercase.  Non-ASCII characters are not changed.
    fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        // Ensure that is a valid email address by parsing it.
        // and return the errors that it returns.
        // This is also done in hagrid.
        let email_address = email_address.as_ref();
        let v: Vec<&str> = email_address.split('@').collect();
        if v.len() != 2 {
            return Err(Error::MalformedEmail(email_address.into()).into())
        };

        // Convert to lowercase without tailoring, i.e. without taking
        // any locale into account.  See:
        // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
        let email = EmailAddress {
            local_part: v[0].to_lowercase(),
            domain: v[1].to_lowercase()
        };
        Ok(email)
    }
}


/// Stores the parts needed to create a Web Key Directory URL.
#[derive(Clone)]
pub struct WkdUrl {
    domain: String,
    local_encoded: String,
    local_part: String,
}


impl WkdUrl {
    /// Returns a WkdUrl from an email address string.or error.
    pub fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        let email = EmailAddress::from(email_address)?;
        let local_encoded = encode_local_part(&email.local_part);
        let wkd_url = WkdUrl {
            domain : email.domain,
            local_encoded : local_encoded,
            local_part : email.local_part,
        };
        Ok(wkd_url)
    }

    /// Returns an URL string from a WkdUrl.
    pub fn to_string<T>(self, direct_method: T) -> Result<String>
            where T: Into<Option<bool>> {
        let direct_method = direct_method.into().unwrap_or(false);
        let authority;
        let path;
        if direct_method {
            authority = self.domain;
            path = ".well-known/openpgpkey/hu/".to_string() +
                   &self.local_encoded;
        } else {
            authority = "openpgpkey.".to_string() + &self.domain;
            path = ".well-known/openpgpkey/".to_string() + &self.domain +
                   "/hu/" + &self.local_encoded;
        };
        let path_and_query = path + "?l=" + &self.local_part;
        let url_string = "https://".to_string() + &authority + "/"
            + &path_and_query + ":443";
        Ok(url_string)
    }

    /// Returns an url::Url.
    pub fn to_url<T>(self, direct_method: T) -> Result<Url>
            where T: Into<Option<bool>> {
        let url_string = self.to_string(direct_method)?;
        let url = Url::parse(url_string.as_str())?;
        Ok(url)
    }

    /// Returns an hyper::Uri.
    pub fn to_uri<T>(self, direct_method: T) -> Result<Uri>
            where T: Into<Option<bool>> {
        // let url = self.to_url(direct_method)?;
        let url_string = self.to_string(direct_method)?;
        let uri = url_string.as_str().parse::<Uri>()?;
        Ok(uri)
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


/// Parse an HTTP response body that may contain TPKs and filter them based on
/// whether they contain a userid with the given email address.
///
/// [draft-koch]:
/// The key needs to carry a User ID packet ([RFC4880]) with that mail address.
pub(crate) fn parse_body<S: AsRef<str>>(body: &[u8], email_address: S)
        -> Result<Vec<TPK>> {
    let email_address = email_address.as_ref();
    // This will fail on the first packet that can not be parsed.
    let packets = TPKParser::from_bytes(&body)?;
    // Collect only the correct packets.
    let tpks: Vec<TPK> = packets.flatten().collect();
    // Collect only the TPKs that contain the email in any of their userids
    let valid_tpks: Vec<TPK> = tpks.iter()
        // XXX: This filter could become a TPK method, but it adds other API
        // method to maintain
        .filter(|tpk| {tpk.userids()
            .any(|uidb|
                if let Ok(Some(a)) = uidb.userid().address() {
                    a == email_address
                } else { false })
        }).cloned().collect();
    if valid_tpks.is_empty() {
        Err(Error::EmailNotInUserids(email_address.into()).into())
    } else {
        Ok(valid_tpks)
    }
}


#[cfg(test)]
mod tests {
    use openpgp::serialize::Serialize;
    use openpgp::tpk::TPKBuilder;

    use super::*;

    #[test]
    fn encode_local_part_works() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }


    #[test]
    fn email_address_from() {
        let email_address = EmailAddress::from("test1@example.com").unwrap();
        assert_eq!(email_address.domain, "example.com");
        assert_eq!(email_address.local_part, "test1");
        assert!(EmailAddress::from("thisisnotanemailaddress").is_err());
    }

    #[test]
    fn wkd_url_roundtrip() {
        // Advanced method
        let expected_url =
            "https://openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        let wkd_url = WkdUrl::from("test1@example.com").unwrap();
        assert_eq!(expected_url, wkd_url.clone().to_string(None).unwrap());
        assert_eq!(Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(None).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.clone().to_uri(None).unwrap());

        // Direct method
        let expected_url =
            "https://example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1";
        assert_eq!(expected_url, wkd_url.clone().to_string(None).unwrap());
        assert_eq!(Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(None).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.to_uri(None).unwrap());
    }

    #[test]
    fn test_parse_body() {
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        tpk.serialize(&mut buffer).unwrap();
        // FIXME!!!!
        let valid_tpks = parse_body(&buffer, "juga@sequoia.org");
        // The userid is not in the TPK
        assert!(valid_tpks.is_err());
        // XXX: add userid to the tpk, instead of creating a new one
        // tpk.add_userid("juga@sequoia.org");
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .add_userid("juga@sequoia.org")
            .generate()
            .unwrap();
        tpk.serialize(&mut buffer).unwrap();
        let valid_tpks = parse_body(&buffer, "juga@sequoia.org");
        assert!(valid_tpks.is_ok());
        assert!(valid_tpks.unwrap().len() == 1);
        // XXX: Test with more TPKs
    }
}
