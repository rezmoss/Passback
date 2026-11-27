//! Canonical binary encoding.
//!
//! Signed and hashed structures must have exactly one encoding, so they use this
//! hand-written format instead of a general serializer: fixed field order,
//! big-endian integers, `u32` length prefixes, hard size limits, and no trailing bytes.

use crate::{Error, Result};

/// Largest single variable-length field (1 GiB, the vault body limit). Reads return
/// slices of the input, so this bounds work, not allocation.
pub const MAX_FIELD: usize = 1 << 30;

/// Append-only encoder.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    pub fn new() -> Self {
        Self::default()
    }
    /// New writer with room for `n` bytes. Use when the encoding will hold secrets, so
    /// growing the buffer never leaves a stale copy behind in freed memory.
    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }
    /// Write one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    /// Write a big-endian u16.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write a big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write a big-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write raw bytes with no length prefix (fixed-size fields).
    pub fn fixed(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }
    /// Write a `u32`-length-prefixed byte string.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        assert!(v.len() <= MAX_FIELD, "field exceeds MAX_FIELD");
        self.u32(v.len() as u32);
        self.fixed(v)
    }
    /// Finish and return the encoding.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Bounds-checked decoder.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Read from `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Malformed("truncated"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// Read a big-endian u16.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    /// Read a big-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    /// Read a big-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    /// Read exactly `N` bytes.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    /// Read `n` raw bytes.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
    /// Read a length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max.min(MAX_FIELD) {
            return Err(Error::Malformed("field too long"));
        }
        self.take(len)
    }
    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }
    /// Fail unless every byte was consumed.
    pub fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let mut w = Writer::new();
        w.u8(7).u16(0x0102).u32(9).u64(u64::MAX).bytes(b"abc").fixed(&[1, 2]);
        let enc = w.finish();
        let mut r = Reader::new(&enc);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert_eq!(r.u32().unwrap(), 9);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.bytes(3).unwrap(), b"abc");
        assert_eq!(r.fixed::<2>().unwrap(), [1, 2]);
        r.finish().unwrap();

        let mut r = Reader::new(&enc[15..]);
        assert!(r.bytes(2).is_err(), "length above max must fail");
        assert!(Reader::new(&[0, 0, 0, 5, 1]).bytes(10).is_err(), "truncated");
        let mut r = Reader::new(&[1, 2]);
        r.u8().unwrap();
        assert!(r.finish().is_err(), "trailing");
    }
}
