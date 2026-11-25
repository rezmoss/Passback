use thiserror::Error;

/// Errors returned by the crypto core.
///
/// Decryption and verification failures are deliberately vague: they do not say
/// which check failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Ciphertext failed authentication, key commitment, or was built for another context.
    #[error("decryption failed")]
    Decrypt,
    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// Input bytes were malformed.
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// The algorithm suite is unknown or no longer accepted.
    #[error("unsupported algorithm suite {0}")]
    UnsupportedSuite(u8),
    /// KDF parameters are outside the accepted range.
    #[error("KDF parameters rejected: {0}")]
    WeakKdf(&'static str),
    /// The unlock factor set is invalid.
    #[error("invalid unlock factors: {0}")]
    Factors(&'static str),
    /// A Secret Key string could not be parsed.
    #[error("invalid secret key: {0}")]
    SecretKeyFormat(&'static str),
    /// The OS random number generator failed.
    #[error("system random number generator failed")]
    Rng,
    /// A built-in self-test failed. The binary must not be used.
    #[error("self-test failed: {0}")]
    SelfTest(&'static str),
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
