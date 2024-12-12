use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use sha3::Digest;
use std::{borrow::Borrow, marker::PhantomData};

use crate::crypto::merkle_tree::{
    keccak::{KeccakDigest, KeccakTwoToOneCRHScheme},
    HashCounter,
};

pub struct EvmKeccakLeafHash<F>(PhantomData<F>);

impl<F: CanonicalSerialize + Send> CRHScheme for EvmKeccakLeafHash<F> {
    type Input = [F];
    type Output = KeccakDigest;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let mut buf = vec![];

        // Replicates the EVM ABI encode behavior:
        // - Encoded array elements are *not* prefixed with their length;
        // - The reverses are necessary to match the endianness of the EVM.
        for element in input.borrow().iter().rev() {
            element.serialize_uncompressed(&mut buf)?;
        }
        buf.reverse();

        let mut h = sha3::Keccak256::new();
        h.update(&buf);

        let mut output = [0; 32];
        output.copy_from_slice(&h.finalize()[..]);
        HashCounter::add();
        Ok(KeccakDigest::from(output))
    }
}

#[derive(Debug, Default, Clone)]
pub struct MerkleTreeEvmParams<F>(PhantomData<F>);

impl<F: CanonicalSerialize + Send> Config for MerkleTreeEvmParams<F> {
    type Leaf = [F];

    type LeafDigest = <EvmKeccakLeafHash<F> as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<KeccakDigest>;
    type InnerDigest = <KeccakTwoToOneCRHScheme as TwoToOneCRHScheme>::Output;

    type LeafHash = EvmKeccakLeafHash<F>;
    type TwoToOneHash = KeccakTwoToOneCRHScheme;
}

// Implements the ability to mask computed hashes when computing the merkle tree
// This helps saving calldata gas
// Credits to starkware's merkle verifier:
// https://github.com/starkware-libs/starkex-contracts/blob/aecf37f2278b2df233edd13b686d0aa9462ada02/evm-verifier/solidity/contracts/MerkleVerifier.sol#L7
pub struct MaskedEvmKeccakLeafHash<F>(PhantomData<F>);

impl<F: CanonicalSerialize + Send> CRHScheme for MaskedEvmKeccakLeafHash<F> {
    type Input = [F];
    type Output = KeccakDigest;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let mut buf = vec![];

        // Replicates the EVM ABI encode behavior:
        // - Encoded array elements are *not* prefixed with their length;
        // - The reverses are necessary to match the endianness of the EVM.
        for element in input.borrow().iter().rev() {
            element.serialize_uncompressed(&mut buf)?;
        }
        buf.reverse();

        let mut h = sha3::Keccak256::new();
        h.update(&buf);

        let mut output = [0; 32];

        // mask the 12 last bytes, i.e. copy the first 20 bytes only
        output[0..20].copy_from_slice(&h.finalize()[..20]);
        HashCounter::add();
        Ok(KeccakDigest::from(output))
    }
}

pub struct MaskedKeccakTwoToOneCRHScheme;

// Implements the ability to mask computed hashes when computing the merkle tree
// This helps saving calldata gas
// Credits to starkware's merkle verifier:
// https://github.com/starkware-libs/starkex-contracts/blob/aecf37f2278b2df233edd13b686d0aa9462ada02/evm-verifier/solidity/contracts/MerkleVerifier.sol#L7
impl TwoToOneCRHScheme for MaskedKeccakTwoToOneCRHScheme {
    type Input = KeccakDigest;
    type Output = KeccakDigest;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let mut h = sha3::Keccak256::new();
        h.update(&left_input.borrow().0);
        h.update(&right_input.borrow().0);
        let mut output = [0; 32];

        // mask the 12 last bytes, i.e. copy the first 20 bytes only
        output[..20].copy_from_slice(&h.finalize()[..20]);
        HashCounter::add();
        Ok(KeccakDigest(output))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MaskedMerkleTreeEvmParams<F>(PhantomData<F>);

impl<F: CanonicalSerialize + Send> Config for MaskedMerkleTreeEvmParams<F> {
    type Leaf = [F];

    type LeafDigest = <MaskedEvmKeccakLeafHash<F> as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<KeccakDigest>;
    type InnerDigest = <MaskedKeccakTwoToOneCRHScheme as TwoToOneCRHScheme>::Output;

    type LeafHash = MaskedEvmKeccakLeafHash<F>;
    type TwoToOneHash = MaskedKeccakTwoToOneCRHScheme;
}
