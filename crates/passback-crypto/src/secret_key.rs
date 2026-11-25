//! The account Secret Key: a 128-bit random value generated on the first device.
//!
//! It is mixed into the unlock key together with the password (two-secret key
//! derivation), so data stolen from a server can't be attacked with password
//! guessing alone. It is shown to the user once, in the emergency kit.
//!
//! Text form: `PB1-` + 26 Crockford base32 chars (128 bits) + 2 checksum chars,
//! grouped by 4: `PB1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "PB1";
const BODY: usize = 26;
const CHECK: usize = 2;

/// An account Secret Key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    /// Generate a new random Secret Key.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::rand::array()?))
    }

    /// Raw bytes.
    pub fn expose(&self) -> &[u8; 16] {
        &self.0
    }

    /// Build from raw bytes.
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    fn checksum(bytes: &[u8; 16]) -> u16 {
        let h = crate::hash::sha256_labeled("passback/v1/secret-key-check", &[bytes]);
        u16::from_be_bytes([h[0], h[1]]) >> 6
    }

    /// Text form for display and the emergency kit.
    pub fn to_display(&self) -> zeroize::Zeroizing<String> {
        let v = u128::from_be_bytes(self.0);
        let mut chars = Vec::with_capacity(BODY + CHECK);
        for i in 0..BODY {
            let shift = 125 - 5 * i as u32;
            chars.push(ALPHABET[((v >> shift) & 31) as usize]);
        }
        let c = Self::checksum(&self.0);
        chars.push(ALPHABET[(c >> 5) as usize & 31]);
        chars.push(ALPHABET[c as usize & 31]);
        let mut out = String::from(PREFIX);
        for group in chars.chunks(4) {
            out.push('-');
            out.push_str(core::str::from_utf8(group).expect("ascii"));
        }
        chars.zeroize();
        zeroize::Zeroizing::new(out)
    }

    /// Parse the text form. Case, spaces and dashes are ignored, and the Crockford
    /// look-alikes O/I/L are accepted for 0/1/1.
    pub fn parse(s: &str) -> Result<Self> {
        let mut clean: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
            s.bytes()
                .filter(|b| !matches!(b, b'-' | b' ' | b'\t'))
                .map(|b| b.to_ascii_uppercase())
                .collect(),
        );
        if !clean.starts_with(PREFIX.as_bytes()) {
            return Err(Error::SecretKeyFormat("missing PB1 prefix"));
        }
        clean.drain(..PREFIX.len());
        if clean.len() != BODY + CHECK {
            return Err(Error::SecretKeyFormat("wrong length"));
        }
        let mut digits = [0u8; BODY + CHECK];
        for (d, &c) in digits.iter_mut().zip(clean.iter()) {
            let c = match c {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            *d = ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or(Error::SecretKeyFormat("invalid character"))? as u8;
        }
        if digits[0] > 7 {
            return Err(Error::SecretKeyFormat("out of range"));
        }
        let mut v: u128 = 0;
        for &d in &digits[..BODY] {
            v = (v << 5) | d as u128;
        }
        let bytes = v.to_be_bytes();
        let want = ((digits[BODY] as u16) << 5) | digits[BODY + 1] as u16;
        digits.zeroize();
        if Self::checksum(&bytes) != want {
            return Err(Error::SecretKeyFormat("checksum mismatch (typo?)"));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parse_roundtrip() {
        for _ in 0..200 {
            let k = SecretKey::generate().unwrap();
            let s = k.to_display();
            assert_eq!(s.len(), 3 + 7 * 5);
            let back = SecretKey::parse(&s).unwrap();
            assert_eq!(back.expose(), k.expose());
            let sloppy = s.to_lowercase().replace('-', " ");
            assert_eq!(SecretKey::parse(&sloppy).unwrap().expose(), k.expose());
        }
        let edge = SecretKey::from_bytes([0xff; 16]);
        assert_eq!(SecretKey::parse(&edge.to_display()).unwrap().expose(), &[0xff; 16]);
    }

    #[test]
    fn typo_is_detected() {
        let k = SecretKey::from_bytes([7; 16]);
        let s = k.to_display();
        let mut b = s.as_bytes().to_vec();
        let i = 6;
        b[i] = if b[i] == b'A' { b'B' } else { b'A' };
        assert!(SecretKey::parse(core::str::from_utf8(&b).unwrap()).is_err());
        assert!(SecretKey::parse("PB2-0000").is_err());
    }
}
