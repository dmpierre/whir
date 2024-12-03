use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use sha3::Digest;
use std::{borrow::Borrow, marker::PhantomData};

use crate::crypto::merkle_tree::{
    keccak::{KeccakDigest, KeccakTwoToOneCRHScheme, LeafH},
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
