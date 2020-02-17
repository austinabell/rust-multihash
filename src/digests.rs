//! # Multihash
//!
//! Implementation of [multihash](https://github.com/multiformats/multihash) in Rust.
//!
//! A `Multihash` is a structure that contains a hashing algorithm, plus some hashed data.
//! A `MultihashRef` is the same as a `Multihash`, except that it doesn't own its data.
//!

use std::convert::TryFrom;

use bytes::{BufMut, Bytes, BytesMut};
use unsigned_varint::{decode as varint_decode, encode as varint_encode};

use crate::errors::{DecodeError, DecodeOwnedError};
use crate::hashes::Code;

/// Represents a valid multihash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Multihash {
    bytes: Bytes,
}

impl Multihash {
    /// Verifies whether `bytes` contains a valid multihash, and if so returns a `Multihash`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Multihash, DecodeOwnedError> {
        if let Err(err) = MultihashRef::from_slice(&bytes) {
            return Err(DecodeOwnedError {
                error: err,
                data: bytes,
            });
        }
        Ok(Multihash {
            bytes: Bytes::from(bytes),
        })
    }

    /// Returns the bytes representation of the multihash.
    pub fn into_bytes(self) -> Vec<u8> {
        self.to_vec()
    }

    /// Returns the bytes representation of the multihash.
    pub fn to_vec(&self) -> Vec<u8> {
        Vec::from(&self.bytes[..])
    }

    /// Returns the bytes representation of this multihash.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Builds a `MultihashRef` corresponding to this `Multihash`.
    pub fn as_ref(&self) -> MultihashRef {
        MultihashRef { bytes: &self.bytes }
    }

    /// Returns which hashing algorithm is used in this multihash.
    pub fn algorithm(&self) -> Code {
        self.as_ref().algorithm()
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &[u8] {
        self.as_ref().digest()
    }
}

impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> PartialEq<MultihashRef<'a>> for Multihash {
    fn eq(&self, other: &MultihashRef<'a>) -> bool {
        &*self.bytes == other.bytes
    }
}

impl TryFrom<Vec<u8>> for Multihash {
    type Error = DecodeOwnedError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Multihash::from_bytes(value)
    }
}

/// Represents a valid multihash.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MultihashRef<'a> {
    bytes: &'a [u8],
}

impl<'a> MultihashRef<'a> {
    /// Creates a `MultihashRef` from the given `input`.
    pub fn from_slice(input: &'a [u8]) -> Result<Self, DecodeError> {
        if input.is_empty() {
            return Err(DecodeError::BadInputLength);
        }

        let (_code, bytes) = varint_decode::u64(&input).map_err(|_| DecodeError::BadInputLength)?;

        let (hash_len, bytes) =
            varint_decode::u64(&bytes).map_err(|_| DecodeError::BadInputLength)?;
        if (bytes.len() as u64) != hash_len {
            return Err(DecodeError::BadInputLength);
        }

        Ok(MultihashRef { bytes: input })
    }

    /// Returns which hashing algorithm is used in this multihash.
    pub fn algorithm(&self) -> Code {
        let (code, _bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid algorithm");
        Code::from_u64(code)
    }

    /// Returns the hashed data.
    pub fn digest(&self) -> &'a [u8] {
        let (_code, bytes) =
            varint_decode::u64(&self.bytes).expect("multihash is known to be valid digest");
        let (_hash_len, bytes) =
            varint_decode::u64(&bytes).expect("multihash is known to be a valid digest");
        &bytes[..]
    }

    /// Builds a `Multihash` that owns the data.
    ///
    /// This operation allocates.
    pub fn to_owned(&self) -> Multihash {
        Multihash {
            bytes: Bytes::copy_from_slice(self.bytes),
        }
    }

    /// Returns the bytes representation of this multihash.
    pub fn as_bytes(&self) -> &'a [u8] {
        &self.bytes
    }
}

impl<'a> PartialEq<Multihash> for MultihashRef<'a> {
    fn eq(&self, other: &Multihash) -> bool {
        self.bytes == &*other.bytes
    }
}

/// The `MultihashDigest` trait specifies an interface common for all multihash functions.
pub trait MultihashDigest {
    /// The Mutlihash byte value.
    const CODE: Code;

    /// Hash some input and return the digest.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hasing.
    fn digest(data: &[u8]) -> Multihash;
}

/// The `DynMultihashDigest` trait is a variant of the `MultihashDigest` that can be used as trait
/// object.
pub trait DynMultihashDigest {
    /// The Mutlihash byte value.
    fn code(&self) -> Code;

    /// Hash some input and return the digest.
    ///
    /// # Panics
    ///
    /// Panics if the digest length is bigger than 2^32. This only happens for identity hasing.
    fn digest(&self, data: &[u8]) -> Multihash;
}

impl<T: MultihashDigest + ?Sized> DynMultihashDigest for T {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
}

/// Wraps a hash digest in Multihash with the given Mutlihash code.
///
/// The size of the hash is determoned by the size of the input hash. If it should be truncated
/// the input data must already be the truncated hash.
pub fn wrap(code: &Code, data: &[u8]) -> Multihash {
    let mut code_buf = varint_encode::u64_buffer();
    let code_varint = varint_encode::u64(code.to_u64(), &mut code_buf);

    let mut size_buf = varint_encode::u64_buffer();
    let size_varint = varint_encode::u64(data.len() as u64, &mut size_buf);

    let len = code_varint.len() + size_varint.len();

    let mut output = BytesMut::with_capacity(len);
    output.put_slice(code_varint);
    output.put_slice(size_varint);
    output.put_slice(data);

    Multihash {
        bytes: output.freeze(),
    }
}
