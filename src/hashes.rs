use blake2b_simd::Params as Blake2b;
use blake2s_simd::Params as Blake2s;
use digest::Digest;
use sha1::Sha1 as Sha1Hasher;
use sha2::{Sha256, Sha512};
use tiny_keccak::{Hasher, Keccak, Sha3};

use crate::digests::{wrap, DynMultihashDigest, Multihash, MultihashDigest};

#[derive(Clone, Debug, PartialEq)]
pub enum Code {
    /// Make it possible to use a custom code that is not part of the enum yet
    Custom(u64),
    /// Hashes that are immplemented in this crate
    Implemented(ImplementedCode),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ImplementedCode {
    /// Identity (Raw binary )
    Identity = 0x00,
    /// SHA-1 (20-byte hash size)
    Sha1 = 0x11,
    /// SHA-256 (32-byte hash size)
    Sha2_256 = 0x12,
    /// SHA-512 (64-byte hash size)
    Sha2_512 = 0x13,
    /// SHA3-224 (28-byte hash size)
    Sha3_224 = 0x17,
    /// SHA3-256 (32-byte hash size)
    Sha3_256 = 0x16,
    /// SHA3-384 (48-byte hash size)
    Sha3_384 = 0x15,
    /// SHA3-512 (64-byte hash size)
    Sha3_512 = 0x14,
    /// Keccak-224 (28-byte hash size)
    Keccak224 = 0x1a,
    /// Keccak-256 (32-byte hash size)
    Keccak256 = 0x1b,
    /// Keccak-384 (48-byte hash size)
    Keccak384 = 0x1c,
    /// Keccak-512 (64-byte hash size)
    Keccak512 = 0x1d,
    /// BLAKE2b-256 (32-byte hash size)
    Blake2b256 = 0xb220,
    /// BLAKE2b-512 (64-byte hash size)
    Blake2b512 = 0xb240,
    /// BLAKE2s-128 (16-byte hash size)
    Blake2s128 = 0xb250,
    /// BLAKE2s-256 (32-byte hash size)
    Blake2s256 = 0xb260,
}

impl Code {
    /// Return the code as integer value.
    pub fn to_u64(&self) -> u64 {
        match *self {
            Self::Custom(code) => code,
            Self::Implemented(code) => code as _,
        }
    }

    /// Return the `Code` based on the integer value. If the code is unknown/not implemented yet
    /// then it returns a `Code::Custom`.
    /// implementes with that value.
    pub fn from_u64(code: u64) -> Self {
        match code {
            0x00 => Code::Implemented(ImplementedCode::Identity),
            0x11 => Code::Implemented(ImplementedCode::Sha1),
            0x12 => Code::Implemented(ImplementedCode::Sha2_256),
            0x13 => Code::Implemented(ImplementedCode::Sha2_512),
            0x14 => Code::Implemented(ImplementedCode::Sha3_512),
            0x15 => Code::Implemented(ImplementedCode::Sha3_384),
            0x16 => Code::Implemented(ImplementedCode::Sha3_256),
            0x17 => Code::Implemented(ImplementedCode::Sha3_224),
            0x1A => Code::Implemented(ImplementedCode::Keccak224),
            0x1B => Code::Implemented(ImplementedCode::Keccak256),
            0x1C => Code::Implemented(ImplementedCode::Keccak384),
            0x1D => Code::Implemented(ImplementedCode::Keccak512),
            0xB220 => Code::Implemented(ImplementedCode::Blake2b256),
            0xB240 => Code::Implemented(ImplementedCode::Blake2b512),
            0xB250 => Code::Implemented(ImplementedCode::Blake2s128),
            0xB260 => Code::Implemented(ImplementedCode::Blake2s256),
            _ => Code::Custom(code),
        }
    }

    /// Return the hasher that is used to create a hash with this code.
    ///
    /// If a custom code is used, `None` is returned.
    pub fn hasher(&self) -> Option<Box<dyn DynMultihashDigest>> {
        match *self {
            Self::Custom(_) => None,
            Self::Implemented(code) => Some(code.hasher()),
        }
    }
}

impl ImplementedCode {
    /// Return the Multihash implementation that does the actual hashing
    fn hasher(self) -> Box<dyn DynMultihashDigest> {
        match self {
            ImplementedCode::Identity => Box::new(Identity),
            ImplementedCode::Sha1 => Box::new(Sha1),
            ImplementedCode::Sha2_256 => Box::new(Sha2_256),
            ImplementedCode::Sha2_512 => Box::new(Sha2_512),
            ImplementedCode::Sha3_224 => Box::new(Sha3_224),
            ImplementedCode::Sha3_256 => Box::new(Sha3_256),
            ImplementedCode::Sha3_384 => Box::new(Sha3_384),
            ImplementedCode::Sha3_512 => Box::new(Sha3_512),
            ImplementedCode::Keccak224 => Box::new(Keccak224),
            ImplementedCode::Keccak256 => Box::new(Keccak256),
            ImplementedCode::Keccak384 => Box::new(Keccak384),
            ImplementedCode::Keccak512 => Box::new(Keccak512),
            ImplementedCode::Blake2b256 => Box::new(Blake2b256),
            ImplementedCode::Blake2b512 => Box::new(Blake2b512),
            ImplementedCode::Blake2s128 => Box::new(Blake2s128),
            ImplementedCode::Blake2s256 => Box::new(Blake2s256),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Identity;
impl MultihashDigest for Identity {
    const CODE: Code = Code::Implemented(ImplementedCode::Identity);

    fn digest(data: &[u8]) -> Multihash {
        if (data.len() as u64) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less the 2^32.")
        }
        wrap(&Self::CODE, &data)
    }
}

#[derive(Clone, Debug)]
pub struct Sha1;
impl MultihashDigest for Sha1 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha1);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Sha1Hasher::from(&data).digest().bytes();
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha2_256;
impl MultihashDigest for Sha2_256 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha2_256);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Sha256::digest(&data);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha2_512;
impl MultihashDigest for Sha2_512 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha2_512);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Sha512::digest(&data);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_224;
impl MultihashDigest for Sha3_224 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha3_224);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 28];
        let mut sha3 = Sha3::v224();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_256;
impl MultihashDigest for Sha3_256 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha3_256);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_384;
impl MultihashDigest for Sha3_384 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha3_384);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 48];
        let mut sha3 = Sha3::v384();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Sha3_512;
impl MultihashDigest for Sha3_512 {
    const CODE: Code = Code::Implemented(ImplementedCode::Sha3_512);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 64];
        let mut sha3 = Sha3::v512();
        sha3.update(&data);
        sha3.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak224;
impl MultihashDigest for Keccak224 {
    const CODE: Code = Code::Implemented(ImplementedCode::Keccak224);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 28];
        let mut keccak = Keccak::v224();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak256;
impl MultihashDigest for Keccak256 {
    const CODE: Code = Code::Implemented(ImplementedCode::Keccak256);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 32];
        let mut keccak = Keccak::v256();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak384;
impl MultihashDigest for Keccak384 {
    const CODE: Code = Code::Implemented(ImplementedCode::Keccak384);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 48];
        let mut keccak = Keccak::v384();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Keccak512;
impl MultihashDigest for Keccak512 {
    const CODE: Code = Code::Implemented(ImplementedCode::Keccak512);

    fn digest(data: &[u8]) -> Multihash {
        let mut digest = [0; 64];
        let mut keccak = Keccak::v512();
        keccak.update(&data);
        keccak.finalize(&mut digest);
        wrap(&Self::CODE, &digest)
    }
}

#[derive(Clone, Debug)]
pub struct Blake2b256;
impl MultihashDigest for Blake2b256 {
    const CODE: Code = Code::Implemented(ImplementedCode::Blake2b256);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2b::new()
            .hash_length(32)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2b512;
impl MultihashDigest for Blake2b512 {
    const CODE: Code = Code::Implemented(ImplementedCode::Blake2b512);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2b::new()
            .hash_length(64)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s128;
impl MultihashDigest for Blake2s128 {
    const CODE: Code = Code::Implemented(ImplementedCode::Blake2s128);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2s::new()
            .hash_length(16)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Blake2s256;
impl MultihashDigest for Blake2s256 {
    const CODE: Code = Code::Implemented(ImplementedCode::Blake2s256);

    fn digest(data: &[u8]) -> Multihash {
        let digest = Blake2s::new()
            .hash_length(32)
            .to_state()
            .update(&data)
            .finalize();
        wrap(&Self::CODE, &digest.as_bytes())
    }
}
