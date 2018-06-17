use std::fmt;

use CompressedData;
use Packet;
use Container;
use constants::CompressionAlgorithm;

impl fmt::Debug for CompressedData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CompressedData")
            .field("algo", &self.algo)
            .field("children",
                   &self.common.children.as_ref()
                       .map(|c| &c.packets).unwrap_or(&Vec::new()))
            .field("body (bytes)",
                   &self.common.body.as_ref().unwrap_or(&b"".to_vec()).len())
            .finish()
    }
}

impl CompressedData {
    /// Returns a new `CompressedData` packet.
    pub fn new(algo: CompressionAlgorithm) -> Self {
        CompressedData {
            common: Default::default(),
            algo: algo,
        }
    }

    /// Adds a new packet to the container.
    pub fn push(mut self, packet: Packet) -> Self {
        if self.common.children.is_none() {
            self.common.children = Some(Container::new());
        }
        self.common.children.as_mut().unwrap().push(packet);
        self
    }

    /// Inserts a new packet to the container at a particular index.
    /// If `i` is 0, the new packet is insert at the front of the
    /// container.  If `i` is one, it is inserted after the first
    /// packet, etc.
    pub fn insert(mut self, i: usize, packet: Packet) -> Self {
        if self.common.children.is_none() {
            self.common.children = Some(Container::new());
        }
        self.common.children.as_mut().unwrap().insert(i, packet);
        self
    }

    /// Convert the `CompressedData` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::CompressedData(self)
    }
}
