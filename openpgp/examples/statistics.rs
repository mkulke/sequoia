/// Collects statistics about the SKS packet dump using the openpgp
/// crate, Sequoia's low-level API.
///
/// Note that to achieve reasonable performance, you need to compile
/// Sequoia and this program with optimizations:
///
///     % cargo run -p openpgp --example statistics --release

use std::env;
extern crate sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::constants::SignatureType;
use openpgp::packet::{BodyLength, Tag};
use openpgp::parse::{PacketParserResult, PacketParser};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Collects statistics about OpenPGP packet dumps.\n\n\
                Usage: {} <packet-dump>\n", args[0]);
    }

    // Global stats.
    let mut packet_count = 0;
    let mut packet_size = 0 as usize;

    // Per-tag statistics.
    let mut tags_count = vec![0; 64];
    let mut tags_unknown = vec![0; 64];
    let mut tags_size_bytes = vec![0 as usize; 64];
    let mut tags_size_count = vec![0; 64];
    let mut tags_size_min = vec![::std::u32::MAX; 64];
    let mut tags_size_max = vec![0; 64];
    let mut sigs_count = vec![0; 256];

    // Per-TPK statistics.
    let mut tpk_count = 0;
    let mut tpk = PerTPK::min();
    let mut tpk_min = PerTPK::max();
    let mut tpk_max = PerTPK::min();

    // Create a parser.
    let mut ppr = PacketParser::from_file(&args[1])
        .expect("Failed to create reader");

    // Iterate over all packets.
    while let PacketParserResult::Some(pp) = ppr {
        // While the packet is in the parser, get some data for later.
        let size = match pp.header().length {
            BodyLength::Full(n) => Some(n),
            _ => None,
        };

        // Get the packet and advance the parser.
        let (packet, tmp) = pp.next().expect("Failed to get next packet");
        ppr = tmp;

        packet_count += 1;
        if let Some(n) = size {
            packet_size += n as usize;
        }
        let i = u8::from(packet.tag()) as usize;
        tags_count[i] += 1;

        match packet {
            // If a new TPK starts, update TPK statistics.
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if tpk_count > 0 {
                    tpk.update_min_max(&mut tpk_min, &mut tpk_max);
                }
                tpk_count += 1;
                tpk = PerTPK::min();
            },

            Packet::Signature(ref sig) => {
                sigs_count[u8::from(sig.sigtype()) as usize] += 1;
                tpk.sigs[u8::from(sig.sigtype()) as usize] += 1;
            },

            _ => (),
        }

        if let Packet::Unknown(_) = packet {
            tags_unknown[i] += 1;
        } else {
            // Only record size statistics of packets we successfully
            // parsed.
            if let Some(n) = size {
                tags_size_bytes[i] += n as usize;
                tags_size_count[i] += 1;
                if n < tags_size_min[i] {
                    tags_size_min[i] = n;
                }
                if n > tags_size_max[i] {
                    tags_size_max[i] = n;
                }

                tpk.bytes += n as usize;
            }

            tpk.packets += 1;
            tpk.tags[i] += 1;
        }
    }
    tpk.update_min_max(&mut tpk_min, &mut tpk_max);

    // Print statistics.
    println!("# Packet statistics\n\n\
              {:>22} {:>9} {:>9} {:>9} {:>9} {:>9}",
             "", "count", "unknown",
             "min size", "mean size", "max size");
    println!("-------------------------------------------------------\
              -----------------");

    println!("{:>22}", "- Packets -");
    for t in 0..64 {
        let count = tags_count[t];
        if count > 0 {
            println!("{:>22} {:>9} {:>9} {:>9} {:>9} {:>9}",
                     format!("{:?}", Tag::from(t as u8)),
                     count,
                     tags_unknown[t],
                     tags_size_min[t],
                     tags_size_bytes[t] / tags_size_count[t],
                     tags_size_max[t]);
        }
    }

    println!("\n{:>22}", "- Signatures -");
    for t in 0..256 {
        let max = tpk_max.sigs[t];
        if max > 0 {
            println!("{:>22} {:>9}",
                     format!("{:?}", SignatureType::from(t as u8)),
                     sigs_count[t]);
        }
    }

    if tpk_count == 0 {
        return;
    }

    println!();
    println!("# TPK statistics\n\n\
              {:>22} {:>9} {:>9} {:>9}",
             "", "min", "mean", "max");
    println!("----------------------------------------------------");
    println!("{:>22} {:>9} {:>9} {:>9}",
             "Size (packets)",
             tpk_min.packets, packet_count / tpk_count, tpk_max.packets);
    println!("{:>22} {:>9} {:>9} {:>9}",
             "Size (bytes)",
             tpk_min.bytes, packet_size / tpk_count, tpk_max.bytes);

    println!("\n{:>22}", "- Packets -");
    for t in 0..64 {
        let max = tpk_max.tags[t];
        if t as u8 != Tag::PublicKey.into() && max > 0 {
            println!("{:>22} {:>9} {:>9} {:>9}",
                     format!("{:?}", Tag::from(t as u8)),
                     tpk_min.tags[t],
                     tags_count[t] / tpk_count,
                     max);
        }
    }

    println!("\n{:>22}", "- Signatures -");
    for t in 0..256 {
        let max = tpk_max.sigs[t];
        if max > 0 {
            println!("{:>22} {:>9} {:>9} {:>9}",
                     format!("{:?}",
                             SignatureType::from(t as u8)),
                     tpk_min.sigs[t],
                     sigs_count[t] / tpk_count,
                     max);
        }
    }
}

struct PerTPK {
    packets: usize,
    bytes: usize,
    tags: Vec<u32>,
    sigs: Vec<u32>,
}

impl PerTPK {
    fn min() -> Self {
        PerTPK {
            packets: 0,
            bytes: 0,
            tags: vec![0; 64],
            sigs: vec![0; 256],
        }
    }

    fn max() -> Self {
        PerTPK {
            packets: ::std::usize::MAX,
            bytes: ::std::usize::MAX,
            tags: vec![::std::u32::MAX; 64],
            sigs: vec![::std::u32::MAX; 256],
        }
    }

    fn update_min_max(&self, min: &mut PerTPK, max: &mut PerTPK) {
        if self.packets < min.packets {
            min.packets = self.packets;
        }
        if self.packets > max.packets {
            max.packets = self.packets;
        }
        if self.bytes < min.bytes {
            min.bytes = self.bytes;
        }
        if self.bytes > max.bytes {
            max.bytes = self.bytes;
        }
        for i in 0..64 {
            if self.tags[i] < min.tags[i] {
                min.tags[i] = self.tags[i];
            }
            if self.tags[i] > max.tags[i] {
                max.tags[i] = self.tags[i];
            }
        }
        for i in 0..256 {
            if self.sigs[i] < min.sigs[i] {
                min.sigs[i] = self.sigs[i];
            }
            if self.sigs[i] > max.sigs[i] {
                max.sigs[i] = self.sigs[i];
            }
        }
    }
}
