// Copyright 2019-2024 Parity Technologies (UK) Ltd.
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! The "default" Substrate/Polkadot Signature type. This is used in codegen, as well as signing related bits.
//! This doesn't contain much functionality itself, but is easy to convert to/from an `sp_runtime::MultiSignature`
//! for instance, to gain functionality without forcing a dependency on Substrate crates here.

use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// A Dilithium signature + public key bundle, matching the runtime’s
/// `sp_runtime::DilithiumMultiSig` layout used inside `MultiSignature::Dilithium`.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug, TypeInfo, Ord, PartialOrd)]
pub struct DilithiumMultiSig {
    /// Raw Dilithium signature bytes.
    pub signature: [u8; 4627],
    /// Raw Dilithium public key bytes.
    pub public: [u8; 2592],
}


/// Signature container that can store known signature types. This is a simplified version of
/// `sp_runtime::MultiSignature`. To obtain more functionality, convert this into that type.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, Debug, TypeInfo)]
pub enum MultiSignature {
    /// An Ed25519 signature (64 bytes).
    Ed25519([u8; 64]),
    /// An Sr25519 signature (64 bytes).
    Sr25519([u8; 64]),
    /// An ECDSA/secp256k1 signature (65 bytes, incl. recovery id).
    Ecdsa([u8; 65]),
    /// An ECDSA/secp256k1 signature but with a different address derivation.
    /// Runtime uses `ecdsa::KeccakSignature`, which SCALE-encodes as 65 bytes.
    Eth([u8; 65]),
    /// A Dilithium signature plus the public key used to derive the account id.
    Dilithium(DilithiumMultiSig),
}