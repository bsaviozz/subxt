// signer/src/dilithium.rs
//! Dilithium (ml_dsa_87) keypair implementation compatible with your runtime:
//! `MultiSignature::Dilithium(DilithiumMultiSig { signature, public })`
//! where `AccountId32 = blake2_256(public)`.

use crate::crypto::seed_from_entropy;
use core::str::FromStr;
use qp_rusty_crystals_dilithium::ml_dsa_87;
use secrecy::ExposeSecret;
use thiserror::Error as DeriveError;

/// Seed length (bytes) used to generate a Dilithium keypair (matches runtime).
pub const SEED_LEN: usize = 32;
/// Dilithium public key length (bytes) for ml_dsa_87 (matches runtime).
pub const PUBLIC_KEY_LEN: usize = 2592;
/// Dilithium signature length (bytes) for ml_dsa_87 (matches runtime).
pub const SIGNATURE_LEN: usize = 4627;

/// Seed bytes used to generate a keypair.
pub type SecretKeyBytes = [u8; SEED_LEN];

/// Raw Dilithium public key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Runtime-compatible Dilithium signature bundle: signature bytes + public key bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBundle {
    /// Raw Dilithium signature bytes.
    pub signature: [u8; SIGNATURE_LEN],
    /// Raw Dilithium public key bytes.
    pub public: [u8; PUBLIC_KEY_LEN],
}

/// A Dilithium keypair wrapper.
#[derive(Clone)]
pub struct Keypair(pub ml_dsa_87::Keypair);

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair").finish_non_exhaustive()
    }
}

impl Keypair {
    /// Create a keypair from a BIP-39 mnemonic phrase and optional password.
    pub fn from_phrase(mnemonic: &bip39::Mnemonic, password: Option<&str>) -> Result<Self, Error> {
        let (arr, len) = mnemonic.to_entropy_array();
        let big_seed =
            seed_from_entropy(&arr[0..len], password.unwrap_or("")).ok_or(Error::InvalidSeed)?;

        let seed: SecretKeyBytes = big_seed[..SEED_LEN]
            .try_into()
            .expect("seed length is SEED_LEN");

        Ok(Self(ml_dsa_87::Keypair::generate(&seed)))
    }

    /// Create a keypair from a 32-byte seed.
    pub fn from_seed(seed: SecretKeyBytes) -> Self {
        Self(ml_dsa_87::Keypair::generate(&seed))
    }

    /// Obtain the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public.to_bytes())
    }

    /// Sign a message (Subxt signer payload bytes) and return the runtime-compatible bundle:
    /// `{ signature, public }`.
    ///
    /// IMPORTANT: matches runtime: `sign(message, None, None)` (no ctx, no hedge, no prehash).
    pub fn sign(&self, message: &[u8]) -> SignatureBundle {
        let sig = self.0.sign(message, None, None); // [u8; 4627]
        let pk = self.0.public.to_bytes(); // [u8; 2592]
        SignatureBundle {
            signature: sig,
            public: pk,
        }
    }
}

/// Verify signature bundle against a message.
pub fn verify<M: AsRef<[u8]>>(sig: &SignatureBundle, message: M) -> bool {
    let Ok(pk) = ml_dsa_87::PublicKey::from_bytes(&sig.public) else {
        return false;
    };
    pk.verify(message.as_ref(), &sig.signature, None)
}

/// Errors that can occur when creating a keypair.
#[derive(Debug, PartialEq, DeriveError)]
pub enum Error {
    /// Invalid seed.
    #[error("Invalid seed (was it the wrong length?)")]
    InvalidSeed,
    /// Invalid phrase.
    #[error("Cannot parse phrase: {0}")]
    Phrase(bip39::Error),
}

impl From<bip39::Error> for Error {
    fn from(err: bip39::Error) -> Self {
        Error::Phrase(err)
    }
}

#[cfg(feature = "subxt")]
mod subxt_compat {
    use super::*;
    use subxt_core::config::Config;
    use subxt_core::tx::signer::Signer as SignerT;
    use subxt_core::utils::{AccountId32, MultiAddress, MultiSignature};
    use subxt_core::utils::DilithiumMultiSig;

    impl From<SignatureBundle> for DilithiumMultiSig {
        fn from(v: SignatureBundle) -> Self {
            DilithiumMultiSig {
                signature: v.signature,
                public: v.public,
            }
        }
    }

    impl From<SignatureBundle> for MultiSignature {
        fn from(v: SignatureBundle) -> Self {
            MultiSignature::Dilithium(v.into())
        }
    }

    impl From<PublicKey> for AccountId32 {
        fn from(value: PublicKey) -> Self {
            value.to_account_id()
        }
    }

    impl<T> From<PublicKey> for MultiAddress<AccountId32, T> {
        fn from(value: PublicKey) -> Self {
            value.to_address()
        }
    }

    impl PublicKey {
        /// Matches runtime IdentifyAccount:
        /// `AccountId32 = blake2_256(dilithium_public_key_bytes)`.
        pub fn to_account_id(self) -> AccountId32 {
            AccountId32(sp_crypto_hashing::blake2_256(self.as_ref()))
        }

        pub fn to_address<T>(self) -> MultiAddress<AccountId32, T> {
            MultiAddress::Id(self.to_account_id())
        }
    }

    impl<T: Config> SignerT<T> for Keypair
    where
        T::AccountId: From<PublicKey>,
        T::Address: From<PublicKey>,
        T::Signature: From<SignatureBundle>,
    {
        fn account_id(&self) -> T::AccountId {
            self.public_key().into()
        }

        fn sign(&self, signer_payload: &[u8]) -> T::Signature {
            self.sign(signer_payload).into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let phrase = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        let mnemonic = bip39::Mnemonic::parse(phrase).unwrap();
        let kp = Keypair::from_phrase(&mnemonic, None).unwrap();

        let msg = b"hello";
        let sig = kp.sign(msg);
        assert!(verify(&sig, msg));
        assert_eq!(sig.public, kp.public_key().0);
    }
}
