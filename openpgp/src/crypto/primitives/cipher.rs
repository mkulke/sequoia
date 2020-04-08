//! Block and stream ciphers.

pub use nettle::cipher::{BlockSizeIs16, Cipher, RawCipherFunctionPointer};
pub use nettle::cipher::{Aes128, Aes192, Aes256};
pub use nettle::cipher::Blowfish;
pub use nettle::cipher::{Camellia128, Camellia192, Camellia256};
pub use nettle::cipher::Cast128;
pub use nettle::cipher::ChaCha;
pub use nettle::cipher::Des3;
pub use nettle::cipher::{Salsa20_128, Salsa20_256};
pub use nettle::cipher::{Salsa20R12_128, Salsa20R12_256};
pub use nettle::cipher::Serpent;
pub use nettle::cipher::Twofish;
