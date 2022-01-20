use sequoia_openpgp::{
    fmt::hex,
    Packet,
    packet::SKESK,
    PacketPile,
    Result,
    parse::Parse,
};

fn main() -> Result<()> {
    let pp = PacketPile::from_file("seipv2.txt")?;
    if let Some(Packet::SKESK(SKESK::V5(v))) = pp.path_ref(&[0]) {
        hex::dump_rfc("s2k derived key", &v.s2k().derive_key(&"password".into(), 16)?);
        hex::dump_rfc("ecrypted key", &v.decrypt(&"password".into())?.1);
    } else {
        panic!()
    }

    Ok(())
}
