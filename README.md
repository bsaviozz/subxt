## ⚠️ Fork Notice

This repository is a fork of Subxt by Parity Technologies.

It has been modified to support **Dilithium (ML-DSA) signatures**, enabling clients to sign and submit post-quantum extrinsics when used as a dependency.

This fork is intended for experimental and benchmarking purposes and does not provide independent releases.

**This branch contains the implementation for ML-DSA-44 signatures**

## Changes in this fork

- Added support for Dilithium (ML-DSA) signature schemes
- Extended signing functionality to support post-quantum extrinsics
- Integrated with modified Substrate node supporting Dilithium verification

## Using this fork

To use Dilithium signing, include this repository as a dependency in your client:

```toml
subxt = { git = "https://github.com/bsaviozz/subxt", branch = "<branch>" }
```
This enables signing extrinsics using Dilithium-compatible keypairs.

```<branch>``` depends on the version of Dilithium you want to use to sign extrinsics:

- "master" contains ML-DSA-87 signing support
- "dilithium-ml-dsa-44" contains ML-DSA-44
- "dilithium-ml-dsa-65" contains ML-DSA-65
