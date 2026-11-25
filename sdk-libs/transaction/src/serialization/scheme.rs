use crate::error::TransactionError;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptedScheme {
    Proofless = 0,
    /// Reserved; anonymous encryption is not implemented in this repository.
    AnonymousRecipient = 1,
    /// Reserved; anonymous encryption is not implemented in this repository.
    AnonymousSender = 2,
    Confidential = 3,
    RingConfidential = 4,
    Merge = 6,
    PlaintextTransfer = 7,
    /// Reserved; ring deposit encryption is not implemented in this repository.
    RingDeposit = 8,
    /// Confidential note encrypted to the decryption-service viewing key.
    ServiceConfidential = 9,
    /// Service-confidential note that names a ring program.
    ServiceRingConfidential = 10,
}

impl EncryptedScheme {
    pub fn from_byte(byte: u8) -> Result<Self, TransactionError> {
        match byte {
            0 => Ok(Self::Proofless),
            1 => Ok(Self::AnonymousRecipient),
            2 => Ok(Self::AnonymousSender),
            3 => Ok(Self::Confidential),
            4 => Ok(Self::RingConfidential),
            6 => Ok(Self::Merge),
            7 => Ok(Self::PlaintextTransfer),
            8 => Ok(Self::RingDeposit),
            9 => Ok(Self::ServiceConfidential),
            10 => Ok(Self::ServiceRingConfidential),
            other => Err(TransactionError::BadDiscriminator(other)),
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// A recipient note opened with the embedded X25519 key. Ring variants mask
    /// the published owner; the other two publish it.
    pub fn opens_confidential_note(self) -> bool {
        matches!(
            self,
            Self::Confidential
                | Self::RingConfidential
                | Self::ServiceConfidential
                | Self::ServiceRingConfidential
        )
    }
}
