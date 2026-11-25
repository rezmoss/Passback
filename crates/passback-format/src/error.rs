use thiserror::Error;

/// Format and state verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    /// Underlying crypto failure (decrypt, signature, malformed field).
    #[error(transparent)]
    Crypto(#[from] passback_crypto::Error),
    /// Not a Passback file, or an unsupported format version.
    #[error("not a Passback vault file or unsupported format version")]
    NotAVault,
    /// The header MAC did not verify after unlocking.
    #[error("vault header was modified")]
    HeaderTampered,
    /// The whole-file signature did not verify.
    #[error("vault file signature is invalid")]
    FileSignature,
    /// A commit does not extend the current head (wrong seq or prev hash).
    #[error("commit chain broken at seq {0}")]
    BrokenChain(u64),
    /// The commit was signed by a key that is not allowed to write this vault.
    #[error("commit signed by an unauthorized key")]
    UnauthorizedSigner,
    /// The state root in a commit does not match the replayed item set.
    #[error("state root mismatch at seq {0}")]
    RootMismatch(u64),
    /// An item version did not increase.
    #[error("item version did not increase")]
    VersionRegression,
    /// A record referenced by a commit is missing or does not match its hash.
    #[error("record missing or does not match commit")]
    RecordMismatch,
    /// The vault is older than one already seen on this device.
    #[error("rollback detected: seen seq {seen}, got seq {got}")]
    Rollback {
        /// Highest sequence number previously seen.
        seen: u64,
        /// Sequence number presented now.
        got: u64,
    },
    /// Two different histories exist for the same sequence number.
    #[error("fork detected at seq {0}")]
    Fork(u64),
    /// A size or count limit was exceeded.
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
}

/// Result alias.
pub type Result<T> = core::result::Result<T, FormatError>;
