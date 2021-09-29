//! Low-level ECDSA tests.

use crate::Result;
use crate::crypto::{mpi, hash::Digest};
use crate::packet::{prelude::*, signature::subpacket::*};
use crate::types::*;

#[test]
fn fips_186_4() -> Result<()> {
    if ! PublicKeyAlgorithm::ECDSA.is_supported() {
        eprintln!("Skipping because ECDSA is not supported.");
        return Ok(());
    }

    fn test(curve: Curve, hash: HashAlgorithm,
            msg: &[u8], x: &[u8], y: &[u8], r: &[u8], s: &[u8])
        -> Result<()>
    {
        if ! curve.is_supported() {
            eprintln!("Skipping because {} is not supported.", curve);
            return Ok(());
        }

        if ! hash.is_supported() {
            eprintln!("Skipping because {} is not supported.", hash);
            return Ok(());
        }

        let now = Timestamp::now();
        let key: Key<key::PublicParts, key::PrimaryRole> =
            Key4::new(now, PublicKeyAlgorithm::ECDSA,
                      mpi::PublicKey::ECDSA {
                          curve: curve.clone(),
                          q: mpi::MPI::new_point(x, y,
                                                 curve.bits().unwrap()),
                      })?.into();
        let mut h = hash.context()?;
        h.update(msg);
        let mut d = h.into_digest()?;
        let mut sig: Signature =
            Signature4::new(SignatureType::Binary,
                            PublicKeyAlgorithm::ECDSA,
                            hash,
                            SubpacketArea::new(vec![
                                Subpacket::new(
                                    SubpacketValue::SignatureCreationTime(now),
                                    false)?,
                            ])?,
                            SubpacketArea::default(),
                            [d[0], d[1]],
                            mpi::Signature::ECDSA {
                                r: mpi::MPI::new(r),
                                s: mpi::MPI::new(s),
                            }).into();

        sig.verify_digest(&key, &d)?;

        // Sanity check: Change the digest and retry.
        d[0] ^= 1;
        sig.verify_digest(&key, &d).unwrap_err();

        Ok(())
    }

    test(
        Curve::NistP256,
        HashAlgorithm::SHA224,
        b"\xfc\x3b\x82\x91\xc1\x72\xda\xe6\x35\xa6\x85\x9f\x52\x5b\xea\xf0\x1c\xf6\x83\x76\x5d\x7c\x86\xf1\xa4\xd7\x68\xdf\x7c\xae\x05\x5f\x63\x9e\xcc\xc0\x8d\x7a\x02\x72\x39\x4d\x94\x9f\x82\xd5\xe1\x2d\x69\xc0\x8e\x24\x83\xe1\x1a\x1d\x28\xa4\xc6\x1f\x18\x19\x31\x06\xe1\x2e\x5d\xe4\xa9\xd0\xb4\xbf\x34\x1e\x2a\xcd\x6b\x71\x5d\xc8\x3a\xe5\xff\x63\x32\x8f\x83\x46\xf3\x55\x21\xca\x37\x8b\x31\x12\x99\x94\x7f\x63\xec\x59\x3a\x5e\x32\xe6\xbd\x11\xec\x4e\xdb\x0e\x75\x30\x2a\x9f\x54\xd2\x12\x26\xd2\x33\x14\x72\x9e\x06\x10\x16",
        b"\xf0\x4e\x9f\x28\x31\xd9\x69\x7a\xe1\x46\xc7\xd4\x55\x2e\x5f\x91\x08\x5c\xc4\x67\x78\x40\x0b\x75\xb7\x6f\x00\x20\x52\x52\x94\x1d",
        b"\xbd\x26\x71\x48\x17\x4c\xd0\xc2\xb0\x19\xcd\x0a\x52\x56\xe2\xf3\xf8\x89\xd1\xe5\x97\x16\x03\x72\xb5\xa1\x33\x9c\x8d\x78\x7f\x10",
        b"\x5d\x95\xc3\x85\xee\xba\x0f\x15\xdb\x0b\x80\xae\x15\x19\x12\x40\x91\x28\xc9\xc8\x0e\x55\x42\x46\x06\x7b\x8f\x6a\x36\xd8\x5e\xa5",
        b"\xdb\x5d\x8a\x1e\x34\x5f\x88\x3e\x4f\xcb\x38\x71\x27\x6f\x17\x0b\x78\x3c\x1a\x1e\x9d\xa6\xb6\x61\x59\x13\x36\x8a\x85\x26\xf1\xc3",
    )?;
    test(
        Curve::NistP256,
        HashAlgorithm::SHA256,
        b"\x21\x18\x8c\x3e\xdd\x5d\xe0\x88\xda\xcc\x10\x76\xb9\xe1\xbc\xec\xd7\x9d\xe1\x00\x3c\x24\x14\xc3\x86\x61\x73\x05\x4d\xc8\x2d\xde\x85\x16\x9b\xaa\x77\x99\x3a\xdb\x20\xc2\x69\xf6\x0a\x52\x26\x11\x18\x28\x57\x8b\xcc\x7c\x29\xe6\xe8\xd2\xda\xe8\x18\x06\x15\x2c\x8b\xa0\xc6\xad\xa1\x98\x6a\x19\x83\xeb\xee\xc1\x47\x3a\x73\xa0\x47\x95\xb6\x31\x9d\x48\x66\x2d\x40\x88\x1c\x17\x23\xa7\x06\xf5\x16\xfe\x75\x30\x0f\x92\x40\x8a\xa1\xdc\x6a\xe4\x28\x8d\x20\x46\xf2\x3c\x1a\xa2\xe5\x4b\x7f\xb6\x44\x8a\x0d\xa9\x22\xbd\x7f\x34",
        b"\x10\x5d\x22\xd9\xc6\x26\x52\x0f\xac\xa1\x3e\x7c\xed\x38\x2d\xcb\xe9\x34\x98\x31\x5f\x00\xcc\x0a\xc3\x9c\x48\x21\xd0\xd7\x37\x37",
        b"\x6c\x47\xf3\xcb\xbf\xa9\x7d\xfc\xeb\xe1\x62\x70\xb8\xc7\xd5\xd3\xa5\x90\x0b\x88\x8c\x42\x52\x0d\x75\x1e\x8f\xaf\x3b\x40\x1e\xf4",
        b"\x54\x2c\x40\xa1\x81\x40\xa6\x26\x6d\x6f\x02\x86\xe2\x4e\x9a\x7b\xad\x76\x50\xe7\x2e\xf0\xe2\x13\x1e\x62\x9c\x07\x6d\x96\x26\x63",
        b"\x4f\x7f\x65\x30\x5e\x24\xa6\xbb\xb5\xcf\xf7\x14\xba\x8f\x5a\x2c\xee\x5b\xdc\x89\xba\x8d\x75\xdc\xbf\x21\x96\x6c\xe3\x8e\xb6\x6f",
    )?;
    test(
        Curve::NistP256,
        HashAlgorithm::SHA384,
        b"\x78\x43\xf1\x57\xef\x85\x66\x72\x2a\x7d\x69\xda\x67\xde\x75\x99\xee\x65\xcb\x39\x75\x50\x8f\x70\xc6\x12\xb3\x28\x91\x90\xe3\x64\x14\x17\x81\xe0\xb8\x32\xf2\xd9\x62\x71\x22\x74\x2f\x4b\x58\x71\xce\xea\xfc\xd0\x9b\xa5\xec\x90\xca\xe6\xbc\xc0\x1a\xe3\x2b\x50\xf1\x3f\x63\x91\x8d\xfb\x51\x77\xdf\x97\x97\xc6\x27\x3b\x92\xd1\x03\xc3\xf7\xa3\xfc\x20\x50\xd2\xb1\x96\xcc\x87\x2c\x57\xb7\x7f\x9b\xdb\x17\x82\xd4\x19\x54\x45\xfc\xc6\x23\x6d\xd8\xbd\x14\xc8\xbc\xbc\x82\x23\xa6\x73\x9f\x6a\x17\xc9\xa8\x61\xe8\xc8\x21\xa6",
        b"\x76\x0b\x56\x24\xbd\x64\xd1\x9c\x86\x6e\x54\xcc\xd7\x4a\xd7\xf9\x88\x51\xaf\xdb\xc3\xdd\xea\xe3\xec\x2c\x52\xa1\x35\xbe\x9c\xfa",
        b"\xfe\xca\x15\xce\x93\x50\x87\x71\x02\xee\xe0\xf5\xaf\x18\xb2\xfe\xd8\x9d\xc8\x6b\x7d\xf0\xbf\x7b\xc2\x96\x3c\x16\x38\xe3\x6f\xe8",
        b"\xbd\xff\x14\xe4\x60\x03\x09\xc2\xc7\x7f\x79\xa2\x59\x63\xa9\x55\xb5\xb5\x00\xa7\xb2\xd3\x4c\xb1\x72\xcd\x6a\xcd\x52\x90\x5c\x7b",
        b"\xb0\x47\x9c\xdb\x3d\xf7\x99\x23\xec\x36\xa1\x04\xa1\x29\x53\x4c\x5d\x59\xf6\x22\xbe\x7d\x61\x3a\xa0\x45\x30\xad\x25\x07\xd3\xa2",
    )?;
    test(
        Curve::NistP256,
        HashAlgorithm::SHA512,
        b"\xea\x95\x85\x9c\xc1\x3c\xcc\xb3\x71\x98\xd9\x19\x80\x3b\xe8\x9c\x2e\xe1\x0b\xef\xdc\xaf\x5d\x5a\xfa\x09\xdc\xc5\x29\xd3\x33\xae\x1e\x4f\xfd\x3b\xd8\xba\x86\x42\x20\x3b\xad\xd7\xa8\x0a\x3f\x77\xee\xee\x94\x02\xee\xd3\x65\xd5\x3f\x05\xc1\xa9\x95\xc5\x36\xf8\x23\x6b\xa6\xb6\xff\x88\x97\x39\x35\x06\x66\x0c\xc8\xea\x82\xb2\x16\x3a\xa6\xa1\x85\x52\x51\xc8\x7d\x93\x5e\x23\x85\x7f\xe3\x5b\x88\x94\x27\xb4\x49\xde\x72\x74\xd7\x75\x4b\xde\xac\xe9\x60\xb4\x30\x3c\x5d\xd5\xf7\x45\xa5\xcf\xd5\x80\x29\x3d\x65\x48\xc8\x32",
        b"\xc6\x2c\xc4\xa3\x9a\xce\x01\x00\x6a\xd4\x8c\xf4\x9a\x3e\x71\x46\x69\x55\xbb\xee\xca\x5d\x31\x8d\x67\x26\x95\xdf\x92\x6b\x3a\xa4",
        b"\xc8\x5c\xcf\x51\x7b\xf2\xeb\xd9\xad\x6a\x9e\x99\x25\x4d\xef\x0d\x74\xd1\xd2\xfd\x61\x1e\x32\x8b\x4a\x39\x88\xd4\xf0\x45\xfe\x6f",
        b"\x6e\x7f\xf8\xec\x7a\x5c\x48\xe0\x87\x72\x24\xa9\xfa\x84\x81\x28\x3d\xe4\x5f\xcb\xee\x23\xb4\xc2\x52\xb0\xc6\x22\x44\x2c\x26\xad",
        b"\x3d\xfa\xc3\x20\xb9\xc8\x73\x31\x81\x17\xda\x6b\xd8\x56\x00\x0a\x39\x2b\x81\x56\x59\xe5\xaa\x2a\x6a\x18\x52\xcc\xb2\x50\x1d\xf3",
    )?;

    test(
        Curve::NistP384,
        HashAlgorithm::SHA224,
        b"\x94\xf8\xbf\xbb\x9d\xd6\xc9\xb6\x19\x3e\x84\xc2\x02\x3a\x27\xde\xa0\x0f\xd4\x83\x56\x90\x9f\xae\xc2\x16\x19\x72\x43\x96\x86\xc1\x46\x18\x4f\x80\x68\x6b\xc0\x9e\x1a\x69\x8a\xf7\xdf\x9d\xea\x3d\x24\xd9\xe9\xfd\x6d\x73\x48\xa1\x46\x33\x9c\x83\x92\x82\xcf\x89\x84\x34\x5d\xc6\xa5\x10\x96\xd7\x4a\xd2\x38\xc3\x52\x33\x01\x2a\xd7\x29\xf2\x62\x48\x1e\xc7\xcd\x64\x88\xf1\x3a\x6e\xba\xc3\xf3\xd2\x34\x38\xc7\xcc\xb5\xa6\x6e\x2b\xf8\x20\xe9\x2b\x71\xc7\x30\xbb\x12\xfd\x64\xea\x17\x70\xd1\xf8\x92\xe5\xb1\xe1\x4a\x9e\x5c",
        b"\x3a\x65\xb2\x6c\x08\x10\x2b\x44\x83\x8f\x8c\x23\x27\xea\x08\x0d\xaf\x1e\x4f\xc4\x5b\xb2\x79\xce\x03\xaf\x13\xa2\xf9\x57\x5f\x0f\xff\x9e\x2e\x44\x23\xa5\x85\x94\xce\x95\xd1\xe7\x10\xb5\x90\xce",
        b"\xfe\x9d\xcb\xcb\x2e\xc6\xe8\xbd\x8e\xd3\xaf\x3f\xf0\xaa\x61\x9e\x90\x0c\xc8\xba\xb3\xf5\x0f\x6e\x5f\x79\xfa\xc0\x91\x64\xfb\x6a\x20\x77\xcc\x4f\x1f\xed\x3e\x9e\xc6\x89\x9e\x91\xdb\x32\x9b\xf3",
        b"\x67\x70\xee\xa9\x36\x9d\x67\x18\xe6\x0d\xd0\xb9\x1a\xee\x84\x5f\xf7\xed\x7e\x0f\xcc\x91\x67\x5f\x56\xd3\x2e\x52\x27\xfd\x3a\x46\x12\xbb\xcb\x15\x56\xfe\x94\xa9\x89\xb9\xe3\xbc\xc2\x5b\xb2\x0e",
        b"\xc4\x30\x72\xf7\x06\xc9\x81\x26\xd0\x6a\x82\xb0\x42\x51\xe3\xec\xb0\xba\x66\xc4\xbb\x6c\xd7\xc0\x25\x91\x9b\x9c\xc6\x01\x9c\xdc\x63\x52\x56\xd2\xa7\xfa\x01\x7b\x80\x6b\x1e\x88\x64\x9d\x2c\x0d",
    )?;
    test(
        Curve::NistP384,
        HashAlgorithm::SHA256,
        b"\x64\xf9\xf0\x5c\x28\x05\xac\xf5\x9c\x04\x7b\x5f\x5d\x2e\x20\xc3\x92\x77\xb6\xd6\x38\x0f\x70\xf8\x7b\x72\x32\x7a\x76\x17\x0b\x87\x2b\xfe\x4b\x25\xc4\x51\x60\x2a\xcf\xb6\xa6\x31\xbb\x88\x5e\x26\x55\xae\xe8\xab\xe4\x4f\x69\xc9\x0f\xb2\x1f\xfd\xe0\x3c\xef\x2a\x45\x2c\x46\x8c\x63\x69\x86\x7d\xfd\x8a\xa2\x6a\xc2\x4e\x16\xaa\x53\xb2\x92\x37\x5a\x8d\x8f\xbf\x98\x8e\x30\x2b\xf0\x00\x88\xe4\xc0\x61\xaa\x12\xc4\x21\xd8\xfe\x3c\xbd\x72\x73\xb0\xe8\x99\x37\x01\xdf\x1c\x59\x43\x1f\x43\x6a\x08\xb8\xe1\x5b\xd1\x23\xd1\x33",
        b"\x16\x6e\x6d\x96\xcb\x60\xd9\x16\xfd\x19\x88\x8a\x2d\xd9\x45\xa3\x30\x6f\xf0\xd7\xb0\xa5\xe3\x07\x29\xf4\x7d\x3d\xac\x3d\xe2\xbe\x3f\xd5\xcd\x74\x37\xe9\xa8\x0d\x6c\x48\xcf\x96\x0d\x2d\x36\xf8",
        b"\xe6\xb2\xb7\x0f\x13\x10\x92\xae\x21\x0f\x29\xcc\x6b\xad\x70\x13\x18\xbd\xdb\x31\xbd\xdf\x92\x16\x95\x85\x5c\x62\x08\x94\x11\x00\xd0\xce\xe5\xd1\x07\x99\xf8\xb8\x35\xaf\xe3\xea\x51\x0e\x82\x29",
        b"\xd9\x12\x4c\x42\x85\x80\x80\xc6\x24\x00\xe4\xd4\xd8\x13\x63\x04\xe0\x3d\x91\x0c\xbe\x9b\x9b\x34\x87\xf4\xd2\x7c\x7e\x05\x40\xa3\x14\xd3\x4b\xef\x8c\x85\x00\x45\xc8\x74\x6c\xa6\x31\xc1\x1c\x42",
        b"\xbb\xf6\x42\x4a\x3b\x70\x16\x6f\xa7\x99\xf4\x9e\x91\x84\x39\xd5\x15\x32\x70\x39\x25\x8e\xf9\xbd\x88\x43\x5a\x59\xc9\xc1\x96\x59\xf8\xec\x3c\x86\x60\x72\x0b\x0c\x08\x35\x4f\xf6\x0e\x0f\x5a\x76",
    )?;
    test(
        Curve::NistP384,
        HashAlgorithm::SHA384,
        b"\x0e\x64\x6c\x6c\x3c\xc0\xf9\xfd\xed\xef\x93\x4b\x71\x95\xfe\x38\x37\x83\x6a\x9f\x6f\x26\x39\x68\xaf\x95\xef\x84\xcd\x03\x57\x50\xf3\xcd\xb6\x49\xde\x74\x5c\x87\x4a\x6e\xf6\x6b\x3d\xd8\x3b\x66\x06\x8b\x43\x35\xbc\x0a\x97\x18\x41\x82\xe3\x96\x5c\x72\x2b\x3b\x1a\xee\x48\x8c\x36\x20\xad\xb8\x35\xa8\x14\x0e\x19\x9f\x4f\xc8\x3a\x88\xb0\x28\x81\x81\x6b\x36\x6a\x09\x31\x6e\x25\x68\x52\x17\xf9\x22\x11\x57\xfc\x05\xb2\xd8\xd2\xbc\x85\x53\x72\x18\x3d\xa7\xaf\x3f\x0a\x14\x14\x8a\x09\xde\xf3\x7a\x33\x2f\x8e\xb4\x0d\xc9",
        b"\xa3\x9a\xc3\x53\xca\x78\x79\x82\xc5\x77\xaf\xf1\xe8\x60\x1c\xe1\x92\xaa\x90\xfd\x0d\xe4\xc0\xed\x62\x7f\x66\xa8\xb6\xf0\x2a\xe5\x13\x15\x54\x3f\x72\xff\xc1\xc4\x8a\x72\x69\xb2\x5e\x7c\x28\x9a",
        b"\x90\x64\xa5\x07\xb6\x6b\x34\x0b\x6e\x0e\x0d\x5f\xfa\xa6\x7d\xd2\x0e\x6d\xaf\xc0\xea\x6a\x6f\xae\xe1\x63\x51\x77\xaf\x25\x6f\x91\x08\xa2\x2e\x9e\xdf\x73\x6a\xb4\xae\x8e\x96\xdc\x20\x7b\x1f\xa9",
        b"\xee\x82\xc0\xf9\x05\x01\x13\x6e\xb0\xdc\x0e\x45\x9a\xd1\x7b\xf3\xbe\x1b\x1c\x8b\x8d\x05\xc6\x00\x68\xa9\x30\x6a\x34\x63\x26\xff\x73\x44\x77\x6a\x95\xf1\xf7\xe2\xe2\xcf\x94\x77\x13\x0e\x73\x5c",
        b"\xaf\x10\xb9\x0f\x20\x3a\xf2\x3b\x75\x00\xe0\x70\x53\x6e\x64\x62\x9b\xa1\x92\x45\xd6\xef\x39\xaa\xb5\x7f\xcd\xb1\xb7\x3c\x4c\x6b\xf7\x07\x0c\x62\x63\x54\x46\x33\xd3\xd3\x58\xc1\x2a\x17\x81\x38",
    )?;
    test(
        Curve::NistP384,
        HashAlgorithm::SHA512,
        b"\xdb\xd8\xdd\xc0\x27\x71\xa5\xff\x73\x59\xd5\x21\x65\x36\xb2\xe5\x24\xa2\xd0\xb6\xff\x18\x0f\xa2\x9a\x41\xa8\x84\x7b\x6f\x45\xf1\xb1\xd5\x23\x44\xd3\x2a\xea\x62\xa2\x3e\xa3\xd8\x58\x4d\xea\xae\xa3\x8e\xe9\x2d\x13\x14\xfd\xb4\xfb\xbe\xcd\xad\x27\xac\x81\x0f\x02\xde\x04\x52\x33\x29\x39\xf6\x44\xaa\x9f\xe5\x26\xd3\x13\xce\xa8\x1b\x9c\x3f\x6a\x8d\xbb\xea\xfc\x89\x9d\x0c\xda\xeb\x1d\xca\x05\x16\x0a\x8a\x03\x96\x62\xc4\xc8\x45\xa3\xdb\xb0\x7b\xe2\xbc\x8c\x91\x50\xe3\x44\x10\x3e\x40\x44\x11\x66\x8c\x48\xaa\x77\x92",
        b"\x54\xc7\x9d\xa7\xf8\xfa\xee\xee\x6f\x3a\x1f\xdc\x66\x4e\x40\x5d\x5c\x0f\xb3\xb9\x04\x71\x5f\x3a\x9d\x89\xd6\xfd\xa7\xea\xbe\x6c\xee\x86\xef\x82\xc1\x9f\xca\x0d\x1a\x29\xe0\x9c\x1a\xcf\xcf\x18",
        b"\x92\x6c\x17\xd6\x87\x78\xeb\x06\x6c\x20\x78\xcd\xb6\x88\xb1\x73\x99\xe5\x4b\xde\x5a\x79\xef\x18\x52\x35\x2a\x58\x96\x7d\xff\x02\xc1\x7a\x79\x2d\x39\xf9\x5c\x76\xd1\x46\xfd\xc0\x86\xfe\x26\xb0",
        b"\x9d\xbf\xa1\x47\x37\x57\x67\xdd\xe8\x1b\x01\x4f\x1e\x3b\xf5\x79\xc4\x4d\xd2\x24\x86\x99\x8a\x9b\x6f\x9e\x09\x20\xe5\x3f\xaa\x11\xee\xd2\x9a\x4e\x23\x56\xe3\x93\xaf\xd1\xf5\xc1\xb0\x60\xa9\x58",
        b"\xe4\xd3\x18\x39\x1f\x7c\xbf\xe7\x0d\xa7\x89\x08\xd4\x2d\xb8\x52\x25\xc8\x5f\x4f\x2f\xf4\x13\xec\xad\x50\xaa\xd5\x83\x3a\xbe\x91\xbd\xd5\xf6\xd6\x4b\x0c\xd2\x81\x39\x8e\xab\x19\x45\x20\x87\xdd",
    )?;

    test(
        Curve::NistP521,
        HashAlgorithm::SHA224,
        b"\xc6\x43\x19\xc8\xaa\x1c\x1a\xe6\x76\x63\x00\x45\xae\x48\x8a\xed\xeb\xca\x19\xd7\x53\x70\x41\x82\xc4\xbf\x3b\x30\x6b\x75\xdb\x98\xe9\xbe\x43\x82\x34\x23\x3c\x2f\x14\xe3\xb9\x7c\x2f\x55\x23\x69\x50\x62\x98\x85\xac\x1e\x0b\xd0\x15\xdb\x0f\x91\x29\x13\xff\xb6\xf1\x36\x1c\x4c\xc2\x5c\x3c\xd4\x34\x58\x3b\x0f\x7a\x5a\x9e\x1a\x54\x9a\xa5\x23\x61\x42\x68\x03\x79\x73\xb6\x5e\xb5\x9c\x0c\x16\xa1\x9a\x49\xbf\xaa\x13\xd5\x07\xb2\x9d\x5c\x7a\x14\x6c\xd8\xda\x29\x17\x66\x51\x00\xac\x9d\xe2\xd7\x5f\xa4\x8c\xb7\x08\xac\x79",
        b"\x00\x01\x88\x36\x6b\x94\x19\xa9\x00\xab\x0e\xd9\x63\x34\x26\xd5\x1e\x25\xe8\xdc\x03\xf4\xf0\xe7\x54\x99\x04\x24\x39\x81\xec\x46\x9c\x8d\x6d\x93\x8f\x67\x14\xee\x62\x0e\x63\xbb\x0e\xc5\x36\x37\x6a\x73\xd2\x4d\x40\xe5\x8a\xd9\xeb\x44\xd1\xe6\x06\x3f\x2e\xb4\xc5\x1d",
        b"\x00\x98\x89\xb9\x20\x3d\x52\xb9\x24\x3f\xd5\x15\x29\x4a\x67\x4a\xfd\x6b\x81\xdf\x46\x37\xff\xdd\xdc\x43\xa7\x41\x47\x41\xed\xa7\x8d\x8a\xa8\x62\xc9\xcb\xbb\x61\x8a\xce\xc5\x5b\xb9\xa2\x9a\xac\x59\x61\x6f\xc8\x04\xa5\x2a\x97\xa9\xfc\x4d\x03\x25\x4f\x44\x69\xef\xfe",
        b"\x01\xd5\x94\x01\xb8\xac\x43\x88\x55\xd5\x45\xa6\x99\x99\x11\x42\x68\x50\x77\xa4\x09\xde\x24\x18\xc7\xcc\xfe\x01\xa4\x77\x1b\x38\x70\xe7\x62\x87\xa9\x65\x4c\x20\x9b\x58\xa1\x2b\x0f\x51\xe8\xdc\x56\x8e\x33\x14\x0a\x6b\x63\x03\x24\xf7\xef\x17\xca\xa6\x4b\xf4\xc1\x39",
        b"\x01\x43\xaf\x36\x0b\x79\x71\x09\x5b\x3b\x50\x67\x9a\x13\xcd\x49\x21\x71\x89\xea\xee\x47\x13\xf4\x20\x17\x20\x17\x52\x16\x57\x3c\x68\xf7\xac\x6f\x68\x8b\xfe\x6e\xb9\x40\xa2\xd9\x71\x80\x9b\xf3\x6c\x0a\x77\xde\xcc\x55\x3b\x02\x5e\xd4\x19\x35\xa3\x89\x86\x85\x18\x3b",
    )?;
    test(
        Curve::NistP521,
        HashAlgorithm::SHA256,
        b"\x91\xf1\xca\x8c\xe6\x68\x1f\x4e\x1f\x11\x7b\x91\x8a\xe7\x87\xa8\x88\x79\x8a\x9d\xf3\xaf\xc9\xd0\xe9\x22\xf5\x1c\xdd\x6e\x7f\x7e\x55\xda\x99\x6f\x7e\x36\x15\xf1\xd4\x1e\x42\x92\x47\x98\x59\xa4\x4f\xa1\x8a\x5a\x00\x66\x62\x61\x0f\x1a\xaa\x28\x84\xf8\x43\xc2\xe7\x3d\x44\x17\x53\xe0\xea\xd5\x1d\xff\xc3\x66\x25\x06\x16\xc7\x06\xf0\x71\x28\x94\x0d\xd6\x31\x2f\xf3\xed\xa6\xf0\xe2\xb4\xe4\x41\xb3\xd7\x4c\x59\x2b\x97\xd9\xcd\x91\x0f\x97\x9d\x7f\x39\x76\x7b\x37\x9e\x7f\x36\xa7\x51\x9f\x2a\x4a\x25\x1e\xf5\xe8\xaa\xe1",
        b"\x01\x67\xd8\xb8\x30\x82\x59\xc7\x30\x93\x1d\xb8\x28\xa5\xf6\x96\x97\xec\x07\x73\xa7\x9b\xde\xdb\xaa\xf1\x51\x14\xa4\x93\x70\x11\xc5\xae\x36\xab\x05\x03\x95\x73\x73\xfe\xe6\xb1\xc4\x65\x0f\x91\xa3\xb0\xc9\x2c\x2d\x60\x4a\x35\x59\xdd\x2e\x85\x6a\x9a\x84\xf5\x51\xd9",
        b"\x01\x9d\x2c\x13\x46\xaa\xda\xa3\x09\x0b\x59\x81\xf5\x35\x32\x43\x30\x0a\x4f\xf0\xab\x96\x1c\x4e\xe5\x30\xf4\x13\x3f\xe8\x5e\x6a\xab\x5b\xad\x42\xe7\x47\xee\xe0\x29\x8c\x2b\x80\x51\xc8\xbe\x70\x49\x10\x9a\xd3\xe1\xb5\x72\xdd\xa1\xca\xc4\xa0\x30\x10\xf9\x9f\x20\x6e",
        b"\x01\xff\x09\x74\x85\xfa\xf3\x2c\xe9\xe0\xc5\x57\xee\x06\x45\x87\xc1\x2c\x48\x34\xe7\xf0\x98\x8c\xf1\x81\xd0\x7b\xa9\xee\x15\xae\x85\xa8\x20\x8b\x61\x85\x00\x80\xfc\x4b\xbe\xdb\xd8\x25\x36\x18\x1d\x43\x97\x34\x59\xf0\xd6\x96\xac\x5e\x6b\x8f\x23\x30\xb1\x79\xd1\x80",
        b"\x00\x30\x6d\xc3\xc3\x82\xaf\x13\xc9\x9d\x44\xdb\x7a\x84\xed\x81\x3c\x87\x19\xc6\xed\x3b\xbe\x75\x1e\xad\x0d\x48\x7b\x5a\x4a\xa0\x18\x12\x98\x62\xb7\xd2\x82\xcc\xe0\xbc\x20\x59\xa5\x6d\x77\x22\xf4\xb2\x26\xf9\xde\xb8\x5d\xa1\x2d\x5b\x40\x64\x8b\xf6\xec\x56\x81\x28",
    )?;
    test(
        Curve::NistP521,
        HashAlgorithm::SHA384,
        b"\x4b\xe8\x1d\xcf\xab\x39\xa6\x4d\x6f\x00\xc0\xd7\xff\xf9\x4d\xab\xdf\x34\x73\xdc\x49\xf0\xe1\x29\x00\xdf\x32\x8d\x65\x84\xb8\x54\xfb\xae\xba\xf3\x19\x4c\x43\x3e\x9e\x21\x74\x33\x42\xe2\xdd\x05\x6b\x44\x5c\x8a\xa7\xd3\x0a\x38\x50\x4b\x36\x6a\x8f\xa8\x89\xdc\x8e\xce\xc3\x5b\x31\x30\x07\x07\x87\xe7\xbf\x0f\x22\xfa\xb5\xbe\xa5\x4a\x07\xd3\xa7\x53\x68\x60\x53\x97\xba\x74\xdb\xf2\x92\x3e\xf2\x0c\x37\xa0\xd9\xc6\x4c\xae\xbc\xc9\x31\x57\x45\x6b\x57\xb9\x8d\x4b\xec\xb1\x3f\xec\xb7\xcc\x7f\x37\x40\xa6\x05\x7a\xf2\x87",
        b"\x00\xcf\xa5\xa8\xa3\xf1\x5e\xb8\xc4\x19\x09\x56\x73\xf1\xd0\xbd\x63\xb3\x96\xff\x98\x13\xc1\x8d\xfe\x5a\xa3\x1f\x40\xb5\x0b\x82\x48\x1f\x9e\xd2\xed\xd4\x7a\xe5\xea\x6a\x48\xea\x01\xf7\xe0\xad\x00\x00\xed\xf7\xb6\x6f\x89\x09\xee\x94\xf1\x41\xd5\xa0\x7e\xfe\x31\x5c",
        b"\x01\x8a\xf7\x28\xf7\x31\x8b\x96\xd5\x7f\x19\xc1\x10\x44\x15\xc8\xd5\x98\x95\x65\x46\x5e\x42\x9b\xc3\x0c\xf6\x5c\xed\x12\xa1\xc5\x85\x6a\xc8\x6f\xca\x02\x38\x8b\xc1\x51\xcf\x89\x95\x9a\x4f\x04\x85\x97\xa9\xe7\x28\xf3\x03\x4a\xa3\x92\x59\xb5\x98\x70\x94\x61\x87\xbf",
        b"\x01\x9c\xf9\x1a\x38\xcc\x20\xb9\x26\x9e\x74\x67\x85\x7b\x1f\xc7\xea\xbb\x8c\xea\x91\x5a\x31\x35\xf7\x27\xd4\x71\xe5\xbf\xcf\xb6\x6d\x32\x1f\xab\xe2\x83\xa2\xcf\x38\xd4\xc5\xa6\xec\xb6\xe8\xcb\xee\x10\x30\x47\x43\x73\xbb\x87\xfc\xdf\xcc\x95\xcf\x85\x7a\x8d\x25\xd0",
        b"\x01\xcf\x9a\xcd\x94\x49\xc5\x75\x89\xc9\x50\xf2\x87\x84\x2f\x9e\x24\x87\xc5\x61\x09\x55\xb2\xb5\x03\x5f\x6a\xac\xfd\x24\x02\xf5\x11\x99\x8a\x1a\x94\x2b\x39\xc3\x07\xfc\x2b\xca\xb2\xc8\xd0\xda\xe9\x4b\x55\x47\xdd\xcc\xfb\x10\x12\xca\x98\x5b\x3e\xdf\x42\xbb\xba\x8b",
    )?;
    test(
        Curve::NistP521,
        HashAlgorithm::SHA512,
        b"\x54\x3c\x37\x4a\xf9\x0c\x34\xf5\x0e\xe1\x95\x00\x6d\x5f\x9d\x8d\xd9\x86\xd0\x9a\xd1\x82\xfc\xbe\xfa\x08\x55\x67\x27\x5e\xee\x1e\x74\x2b\xfe\x0a\xf3\xd0\x58\x67\x5a\xde\xb5\xb9\xf8\x7f\x24\x8b\x00\xa9\xfb\xd2\xaa\x77\x91\x29\x12\x3a\x5b\x98\x3f\x2f\x26\xfc\x3c\xaf\x2e\xa3\x42\x77\x55\x0c\x22\xfe\x8c\x81\x4c\x73\x9b\x46\x97\x2d\x50\x23\x29\x93\xcd\xdd\x63\xa3\xc9\x9e\x20\xf5\xc5\x06\x7d\x9b\x57\xe2\xd5\xdb\x94\x31\x7a\x5a\x16\xb5\xc1\x2b\x5c\x4c\xaf\xbc\x79\xcb\xc2\xf9\x94\x0f\x07\x4b\xbc\x7d\x0d\xc7\x1e\x90",
        b"\x00\x9e\xc1\xa3\x76\x1f\xe3\x95\x80\x73\xb9\x64\x7f\x34\x20\x2c\x5e\x8c\xa2\x42\x8d\x05\x6f\xac\xc4\xf3\xfe\xdc\x70\x77\xfa\x87\xf1\xd1\xeb\x30\xcc\x74\xf6\xe3\xff\x3d\x3f\x82\xdf\x26\x41\xce\xa1\xeb\x3f\xf1\x52\x9e\x8a\x38\x66\xae\x20\x55\xaa\xce\xc0\xbf\x68\xc4",
        b"\x00\xbe\xd0\x26\x1b\x91\xf6\x64\xc3\xff\x53\xe3\x37\xd8\x32\x1c\xb9\x88\xc3\xed\xc0\x3b\x46\x75\x46\x80\x09\x7e\x5a\x85\x85\x24\x5d\x80\xd0\xb7\x04\x5c\x75\xa9\xc5\xbe\x7f\x59\x9d\x3b\x5e\xea\x08\xd8\x28\xac\xb6\x29\x4a\xe5\x15\xa3\xdf\x57\xa3\x7f\x90\x3e\xf6\x2e",
        b"\x00\xce\xf3\xf4\xba\xbe\x6f\x98\x75\xe5\xdb\x28\xc2\x7d\x6a\x19\x7d\x60\x7c\x36\x41\xa9\x0f\x10\xc2\xcc\x2c\xb3\x02\xba\x65\x8a\xa1\x51\xdc\x76\xc5\x07\x48\x8b\x99\xf4\xb3\xc8\xbb\x40\x4f\xb5\xc8\x52\xf9\x59\x27\x3f\x41\x2c\xbd\xd5\xe7\x13\xc5\xe3\xf0\xe6\x7f\x94",
        b"\x00\x09\x7e\xd9\xe0\x05\x41\x6f\xc9\x44\xe2\x6b\xcc\x36\x61\xa0\x9b\x35\xc1\x28\xfc\xcc\xdc\x27\x42\x73\x9c\x8a\x30\x1a\x33\x8d\xd7\x7d\x9d\x13\x57\x16\x12\xa3\xb9\x52\x4a\x61\x64\xb0\x9f\xe7\x36\x43\xbb\xc3\x14\x47\xee\x31\xef\x44\xa4\x90\x84\x3e\x4e\x7d\xb2\x3f",
    )?;

    Ok(())
}
