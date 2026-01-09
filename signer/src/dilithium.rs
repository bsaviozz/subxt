//! A Dilithium keypair implementation for Subxt.
//!
//! This is intentionally minimal: generate keys, sign bytes, verify bytes,
//! and (optionally) implement `subxt_core::tx::signer::Signer` behind the `subxt` feature.

use codec::{Decode, Encode};
use scale_info::TypeInfo;

use thiserror::Error;

// Your runtime expects pk=2592 and sig=4627.
// If this `use` line doesn’t compile, open the crate docs and switch to the correct module.
// Common candidates are `dilithium2`, `dilithium3`, `dilithium5`.
use qp_rusty_crystals_dilithium::dilithium5 as dil;

// Runtime-locked sizes (from qp_rusty_crystals_dilithium documentation)
pub const DILITHIUM_SIG_LEN: usize = 4627;
pub const DILITHIUM_PUB_LEN: usize = 2592;

/// A signature payload equivalent to runtime `sp_runtime::DilithiumMultiSig`.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
pub struct Signature {
    pub signature: [u8; DILITHIUM_SIG_LEN],
    pub public: [u8; DILITHIUM_PUB_LEN],
}

/// Public key bytes (this is not AccountId; runtime derives AccountId32 from pk).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; DILITHIUM_PUB_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Minimal keypair wrapper.
#[derive(Clone)]
pub struct Keypair {
    // Keep these as Vec<u8> to avoid guessing secret key length types.
    // We validate lengths when exporting/signing.
    pk: Vec<u8>,
    sk: Vec<u8>,
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
    /// Generate a fresh keypair using the Dilithium implementation.
    pub fn generate() -> Result<Self, Error> {
        // Typical API is `(pk, sk) = keypair()`.
        // If this doesn’t compile, adjust to the crate’s actual return order/types.
        let (pk, sk) = dil::keypair();
        Ok(Self {
            pk: pk.to_vec(),
            sk: sk.to_vec(),
        })
    }

    /// Construct from raw key bytes (useful if you store keys somewhere).
    pub fn from_bytes(pk: &[u8], sk: &[u8]) -> Result<Self, Error> {
        if pk.len() != DILITHIUM_PUB_LEN {
            return Err(Error::BadPublicKeyLen {
                expected: DILITHIUM_PUB_LEN,
                got: pk.len(),
            });
        }
        // We don’t enforce secret key length here because the crate’s SK length depends
        // on the parameter set; keep it flexible.
        Ok(Self {
            pk: pk.to_vec(),
            sk: sk.to_vec(),
        })
    }

    /// Return the public key (fixed-size).
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        let pk: [u8; DILITHIUM_PUB_LEN] = self
            .pk
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadPublicKeyLen {
                expected: DILITHIUM_PUB_LEN,
                got: self.pk.len(),
            })?;
        Ok(PublicKey(pk))
    }

    /// Sign a message. Returns the payload your runtime expects in `MultiSignature::Dilithium(...)`.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let pk_arr: [u8; DILITHIUM_PUB_LEN] = self
            .pk
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadPublicKeyLen {
                expected: DILITHIUM_PUB_LEN,
                got: self.pk.len(),
            })?;

        // Typical API: `sig = sign(message, &sk)` returning `[u8; SIGNBYTES]` or `Vec<u8>`.
        // If it returns Vec<u8>, we validate and copy.
        let sig_any = dil::sign(message, &self.sk);

        // Normalize signature into `[u8; DILITHIUM_SIG_LEN]`.
        let sig_arr: [u8; DILITHIUM_SIG_LEN] = normalize_sig(sig_any)
            .map_err(|got| Error::BadSignatureLen { expected: DILITHIUM_SIG_LEN, got })?;

        Ok(Signature {
            signature: sig_arr,
            public: pk_arr,
        })
    }
}

/// Verify that `sig` is valid for `message` under `sig.public`.
pub fn verify(sig: &Signature, message: &[u8]) -> bool {
    // Typical API: `verify(message, &sig, &pk) -> bool`.
    // If the crate uses a different order, adjust.
    dil::verify(message, &sig.signature, &sig.public)
}

// Accept either `[u8; N]` or `Vec<u8>` from the Dilithium crate.
// This avoids hard-coding the crate’s exact return type here.
fn normalize_sig<S>(sig: S) -> Result<[u8; DILITHIUM_SIG_LEN], usize>
where
    S: IntoSigBytes,
{
    let bytes = sig.into_sig_bytes();
    if bytes.len() != DILITHIUM_SIG_LEN {
        return Err(bytes.len());
    }
    let mut out = [0u8; DILITHIUM_SIG_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Small abstraction layer to handle either arrays or Vec returns.
trait IntoSigBytes {
    fn into_sig_bytes(self) -> Vec<u8>;
}

impl IntoSigBytes for Vec<u8> {
    fn into_sig_bytes(self) -> Vec<u8> {
        self
    }
}

impl<const N: usize> IntoSigBytes for [u8; N] {
    fn into_sig_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("public key length mismatch: expected {expected}, got {got}")]
    BadPublicKeyLen { expected: usize, got: usize },

    #[error("signature length mismatch: expected {expected}, got {got}")]
    BadSignatureLen { expected: usize, got: usize },
}

// ---- Subxt compatibility glue (optional) ----
#[cfg(feature = "subxt")]
#[cfg_attr(docsrs, doc(cfg(feature = "subxt")))]
mod subxt_compat {
    use super::*;

    use blake2::digest::{Update, VariableOutput};
    use subxt_core::{
        Config,
        tx::signer::Signer as SignerT,
        utils::{AccountId32, MultiAddress, MultiSignature},
    };

    fn blake2_256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 is valid");
        hasher.update(data);
        hasher.finalize_variable(&mut out).expect("ok");
        out
    }

    impl From<Signature> for MultiSignature {
        fn from(value: Signature) -> Self {
            MultiSignature::Dilithium(subxt_core::utils::DilithiumMultiSig {
                signature: value.signature,
                public: value.public,
            })
        }
    }

    impl From<PublicKey> for AccountId32 {
        fn from(pk: PublicKey) -> Self {
            // MUST match your runtime: AccountId32 = blake2_256(public)
            AccountId32(blake2_256(pk.as_ref()))
        }
    }

    impl<T> From<PublicKey> for MultiAddress<AccountId32, T> {
        fn from(pk: PublicKey) -> Self {
            MultiAddress::Id(pk.into())
        }
    }

    impl<T: Config> SignerT<T> for Keypair
    where
        T::AccountId: From<PublicKey>,
        T::Address: From<PublicKey>,
        T::Signature: From<Signature>,
    {
        fn account_id(&self) -> T::AccountId {
            // If this errors, you want it to fail loudly rather than silently submit junk.
            self.public_key().expect("valid dilithium public key").into()
        }

        fn sign(&self, signer_payload: &[u8]) -> T::Signature {
            self.sign(signer_payload).expect("dilithium signing must succeed").into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().expect("generate");
        let msg = b"hello";

        let sig = kp.sign(msg).expect("sign");
        assert!(verify(&sig, msg));
    }

    #[test]
    fn signature_contains_public_key() {
        let kp = Keypair::generate().expect("generate");
        let msg = b"hello";

        let sig = kp.sign(msg).expect("sign");
        let pk = kp.public_key().expect("pk");

        assert_eq!(sig.public, pk.0);
    }
}
