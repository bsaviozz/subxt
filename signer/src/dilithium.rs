use codec::{Decode, Encode};
use scale_info::TypeInfo;

use thiserror::Error;


use qp_rusty_crystals_dilithium::ml_dsa_87 as dil;
use qp_rusty_crystals_dilithium::sign::{
    keypair,
    signature as dil_sign,
    verify as dil_verify,
};

/// Length in bytes of a Dilithium signature for this parameter set.
pub const DILITHIUM_SIG_LEN: usize = dil::SIGNBYTES;
/// Length in bytes of a Dilithium public key for this parameter set.
pub const DILITHIUM_PUB_LEN: usize = dil::PUBLICKEYBYTES;
/// Length in bytes of a Dilithium secret key for this parameter set.
pub const DILITHIUM_SEC_LEN: usize = dil::SECRETKEYBYTES;

/// A signature payload matching the runtime `DilithiumMultiSig` layout (signature + public key).
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
pub struct Signature {
    /// Signature bytes.
    pub signature: [u8; DILITHIUM_SIG_LEN],
    /// Public key bytes corresponding to the signer.
    pub public: [u8; DILITHIUM_PUB_LEN],
}

/// A Dilithium public key (raw bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; DILITHIUM_PUB_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Dilithium keypair wrapper used for signing Subxt extrinsics.
#[derive(Clone)]
pub struct Keypair {
    pk: [u8; DILITHIUM_PUB_LEN],
    sk: [u8; DILITHIUM_SEC_LEN],
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("pk_len", &self.pk.len())
            .field("sk_len", &self.sk.len())
            .finish()
    }
}

impl Keypair {
    /// Generate a new random Dilithium keypair.
    pub fn generate() -> Result<Self, Error> {
        let mut pk = [0u8; DILITHIUM_PUB_LEN];
        let mut sk = [0u8; DILITHIUM_SEC_LEN];

        // qp-rusty-crystals keypair() needs a seed.
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| Error::RandomnessUnavailable)?;

        keypair(&mut pk, &mut sk, &seed);

        Ok(Self { pk, sk })
    }

    /// Construct a keypair from raw public/secret key bytes.
    pub fn from_bytes(pk: &[u8], sk: &[u8]) -> Result<Self, Error> {
        let pk: [u8; DILITHIUM_PUB_LEN] = pk.try_into().map_err(|_| Error::BadPublicKeyLen {
            expected: DILITHIUM_PUB_LEN,
            got: pk.len(),
        })?;

        let sk: [u8; DILITHIUM_SEC_LEN] = sk.try_into().map_err(|_| Error::BadSecretKeyLen {
            expected: DILITHIUM_SEC_LEN,
            got: sk.len(),
        })?;

        Ok(Self { pk, sk })
    }

    /// Return the public key for this keypair.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.pk)
    }

    /// Sign an encoded Subxt signer payload and return a `Signature` (signature + public key).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut sig = [0u8; DILITHIUM_SIG_LEN];

        dil_sign(&mut sig, message, &self.sk, None);

        Signature {
            signature: sig,
            public: self.pk,
        }
    }
}

/// Verify a Dilithium signature over `message`.
pub fn verify_signature(sig: &Signature, message: &[u8]) -> bool {
    // Typical qp-rusty-crystals API: verify(sig, msg, pk) -> bool
    dil_verify(&sig.signature, message, &sig.public)
}

/// Errors that can occur when constructing or using a Dilithium keypair.
#[derive(Debug, Error)]
pub enum Error {
    /// Public key length mismatch.
    #[error("public key length mismatch: expected {expected}, got {got}")]
    BadPublicKeyLen {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// Secret key length mismatch.
    #[error("secret key length mismatch: expected {expected}, got {got}")]
    BadSecretKeyLen {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// Randomness could not be obtained from the OS.
    #[error("randomness unavailable")]
    RandomnessUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().expect("generate");
        let msg = b"hello";

        let sig = kp.sign(msg);
        assert!(verify_signature(&sig, msg));
    }

    #[test]
    fn signature_contains_public_key() {
        let kp = Keypair::generate().expect("generate");
        let msg = b"hello";

        let sig = kp.sign(msg);
        let pk = kp.public_key();

        assert_eq!(sig.public, pk.0);
    }
}
