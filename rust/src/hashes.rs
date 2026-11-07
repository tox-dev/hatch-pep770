//! The hashlib algorithms a RECORD may name.

use digest::Digest;

pub enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha512_224(sha2::Sha512_224),
    Sha512_256(sha2::Sha512_256),
    Sha3_224(sha3::Sha3_224),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
    Blake2b(blake2::Blake2b512),
    Blake2s(blake2::Blake2s256),
}

impl Hasher {
    /// `hashlib.new(name)`, for the algorithms the core implements
    pub fn new(name: &str) -> Option<Self> {
        Some(match name {
            "md5" => Self::Md5(md5::Md5::new()),
            "sha1" => Self::Sha1(sha1::Sha1::new()),
            "sha224" => Self::Sha224(sha2::Sha224::new()),
            "sha256" => Self::Sha256(sha2::Sha256::new()),
            "sha384" => Self::Sha384(sha2::Sha384::new()),
            "sha512" => Self::Sha512(sha2::Sha512::new()),
            "sha512_224" => Self::Sha512_224(sha2::Sha512_224::new()),
            "sha512_256" => Self::Sha512_256(sha2::Sha512_256::new()),
            "sha3_224" => Self::Sha3_224(sha3::Sha3_224::new()),
            "sha3_256" => Self::Sha3_256(sha3::Sha3_256::new()),
            "sha3_384" => Self::Sha3_384(sha3::Sha3_384::new()),
            "sha3_512" => Self::Sha3_512(sha3::Sha3_512::new()),
            "blake2b" => Self::Blake2b(blake2::Blake2b512::new()),
            "blake2s" => Self::Blake2s(blake2::Blake2s256::new()),
            _ => return None,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(hasher) => hasher.update(data),
            Self::Sha1(hasher) => hasher.update(data),
            Self::Sha224(hasher) => hasher.update(data),
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) => hasher.update(data),
            Self::Sha512(hasher) => hasher.update(data),
            Self::Sha512_224(hasher) => hasher.update(data),
            Self::Sha512_256(hasher) => hasher.update(data),
            Self::Sha3_224(hasher) => hasher.update(data),
            Self::Sha3_256(hasher) => hasher.update(data),
            Self::Sha3_384(hasher) => hasher.update(data),
            Self::Sha3_512(hasher) => hasher.update(data),
            Self::Blake2b(hasher) => hasher.update(data),
            Self::Blake2s(hasher) => hasher.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Md5(hasher) => hasher.finalize().to_vec(),
            Self::Sha1(hasher) => hasher.finalize().to_vec(),
            Self::Sha224(hasher) => hasher.finalize().to_vec(),
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
            Self::Sha512_224(hasher) => hasher.finalize().to_vec(),
            Self::Sha512_256(hasher) => hasher.finalize().to_vec(),
            Self::Sha3_224(hasher) => hasher.finalize().to_vec(),
            Self::Sha3_256(hasher) => hasher.finalize().to_vec(),
            Self::Sha3_384(hasher) => hasher.finalize().to_vec(),
            Self::Sha3_512(hasher) => hasher.finalize().to_vec(),
            Self::Blake2b(hasher) => hasher.finalize().to_vec(),
            Self::Blake2s(hasher) => hasher.finalize().to_vec(),
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    crate::record::to_hex(&sha2::Sha256::digest(data))
}
