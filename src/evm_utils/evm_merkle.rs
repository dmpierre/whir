use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::FftField;
use ark_std::log2;

use crate::{
    crypto::merkle_tree::keccak::{KeccakDigest, KeccakTwoToOneCRHScheme},
    evm_utils::hasher::EvmKeccakLeafHash,
};

#[derive(Clone)]
pub struct EVMMultiProof {
    pub depth: u32,
    pub decommitments: Vec<KeccakDigest>,
}

// Implements multi merkle proofs.
// Post: https://ethresear.ch/t/optimizing-merkle-tree-multi-queries/4912/3
pub fn generate_multiproof<
    MerkleConfig: Config<InnerDigest = KeccakDigest, LeafDigest = KeccakDigest>,
    F: FftField,
>(
    mt: &MerkleTree<MerkleConfig>,
    indices: Vec<usize>,
    values: Vec<Vec<F>>,
) -> EVMMultiProof {
    let mut indices = indices.to_vec().clone();
    let mut values = values.clone();
    indices.reverse();
    values.reverse();
    let tree = [
        [mt.root()].to_vec(),
        mt.non_leaf_nodes.clone(),
        mt.leaf_nodes.clone(),
    ]
    .concat();
    let num_leafs = mt.leaf_nodes.len();
    let depth = log2(mt.leaf_nodes.len());
    let num_nodes = 2 * num_leafs;
    let mut known = vec![false; num_nodes];
    assert_eq!(known.len(), tree.len());
    let mut decommitments = vec![];
    for i in indices.clone() {
        known[2_usize.pow(depth as u32) + i] = true;
    }
    for i in (1..=2_usize.pow(depth as u32) - 1).rev() {
        let left = known[2 * i];
        let right = known[2 * i + 1];
        if left & !right {
            decommitments.push(tree[2 * i + 1]);
        }
        if !left & right {
            decommitments.push(tree[2 * i]);
        }
        known[i] = left || right;
    }
    return EVMMultiProof {
        decommitments,
        depth,
    };
}

pub fn verify_multiproof<F: FftField>(
    multi_proof: &EVMMultiProof,
    root: KeccakDigest,
    indices: Vec<usize>,
    values: Vec<Vec<F>>,
) -> bool {
    let mut decommitments = multi_proof.decommitments.clone();
    let mut queue = vec![];
    // we need to iterate in reverse order
    for i in 0..values.len() {
        let tree_idx = 2_usize.pow(multi_proof.depth) + indices[indices.len() - i - 1];
        let hash = EvmKeccakLeafHash::evaluate(&(), values[values.len() - i - 1].clone());
        queue.push((tree_idx, hash.unwrap()));
    }
    loop {
        assert!(queue.len() >= 1);
        let (index, hash) = queue[0];
        queue = queue[1..].to_vec();
        if index == 1 {
            return hash == root;
        } else if index % 2 == 0 {
            let hash_to_push =
                KeccakTwoToOneCRHScheme::evaluate(&(), hash, decommitments[0]).unwrap();
            queue.push((index / 2, hash_to_push));
            decommitments = decommitments[1..].to_vec();
        } else if queue.len() > 0 && queue[0].0 == index - 1 {
            let (_, sibling_hash) = queue[0];
            queue = queue[1..].to_vec();
            let hash_to_push = KeccakTwoToOneCRHScheme::evaluate(&(), sibling_hash, hash).unwrap();
            queue.push((index / 2, hash_to_push));
        } else {
            let hash_to_push =
                KeccakTwoToOneCRHScheme::evaluate(&(), decommitments[0], hash).unwrap();
            queue.push((index / 2, hash_to_push));
            decommitments = decommitments[1..].to_vec();
        }
    }
}

#[cfg(test)]
pub mod tests {
    use rand::distributions::Uniform;
    use rand::prelude::Distribution;

    use crate::crypto::fields::FieldBn256;
    use crate::crypto::merkle_tree::keccak::{self as merkle_tree};
    use crate::evm_utils::evm_merkle::{generate_multiproof, verify_multiproof};
    use crate::evm_utils::hasher::MerkleTreeEvmParams;
    use crate::fs_utils::{EVMFs, KeccakEVMPoW};
    use crate::parameters::{FoldType, MultivariateParameters, SoundnessType, WhirParameters};
    use crate::poly_utils::coeffs::CoefficientList;
    use crate::poly_utils::MultilinearPoint;
    use crate::utils;
    use crate::whir::committer::Witness;
    use crate::whir::Statement;
    use crate::whir::{committer::Committer, parameters::WhirConfig};

    type MerkleConfig = MerkleTreeEvmParams<F>;
    type PowStrategy = KeccakEVMPoW;
    type F = FieldBn256;

    fn merkle_commit(
        num_variables: usize,
        folding_factor: usize,
        num_points: usize,
    ) -> Witness<F, MerkleConfig> {
        let num_coeffs = 1 << num_variables;
        let mut rng = ark_std::test_rng();
        let (leaf_hash_params, two_to_one_params) = merkle_tree::default_config::<F>(&mut rng);
        let mv_params = MultivariateParameters::<F>::new(num_variables);
        let whir_params = WhirParameters::<MerkleConfig, PowStrategy> {
            security_level: 32,
            pow_bits: 0,
            folding_factor,
            leaf_hash_params,
            two_to_one_params,
            soundness_type: SoundnessType::ConjectureList,
            _pow_parameters: Default::default(),
            starting_log_inv_rate: 1,
            fold_optimisation: FoldType::ProverHelps,
        };

        let params = WhirConfig::<F, MerkleConfig, PowStrategy>::new(mv_params, whir_params);
        let polynomial = CoefficientList::new(vec![F::from(1); num_coeffs]);
        let points: Vec<_> = (0..num_points)
            .map(|_| MultilinearPoint::rand(&mut rng, num_variables))
            .collect();
        let _statement = Statement {
            points: points.clone(),
            evaluations: points
                .iter()
                .map(|point| polynomial.evaluate(point))
                .collect(),
        };
        let mut evmfs_merlin = EVMFs::<F>::new();
        let committer = Committer::new(params.clone());
        committer
            .evm_commit(&mut evmfs_merlin, polynomial.clone())
            .unwrap()
    }

    #[test]
    pub fn test_evm_merkle() {
        for num_variables in (4..=20).step_by(2) {
            // number of variables in polynomial
            for folding_factor in 1..4 {
                for i in (1..20).step_by(4) {
                    // number of indices to open
                    let num_points = 1;
                    let witness = merkle_commit(num_variables, folding_factor, num_points);
                    let merkle_tree = witness.merkle_tree.clone();
                    let step = Uniform::new(0, witness.merkle_tree.leaf_nodes.len() - 1);
                    let mut rng = rand::thread_rng();
                    let mut indices: Vec<_> = step.sample_iter(&mut rng).take(i).collect();
                    indices = utils::dedup(indices);
                    // note that indices should be decreasing;
                    // indices.reverse();
                    // get values for the leaves at the specified indexes
                    let fold_size = 1 << folding_factor;
                    let mut values = vec![];
                    for i in &indices {
                        values.push(
                            witness.merkle_leaves[i * fold_size..(i + 1) * fold_size].to_vec(),
                        );
                    }
                    let multiproof =
                        generate_multiproof(&merkle_tree, indices.clone(), values.clone());
                    let verify =
                        verify_multiproof(&multiproof, merkle_tree.root(), indices.clone(), values);
                    assert!(verify);
                }
            }
        }
    }
}
