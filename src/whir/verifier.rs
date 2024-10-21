use std::iter;

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use nimue::{
    plugins::{
        ark::{FieldChallenges, FieldReader},
        pow::{self, PoWChallenge},
    },
    Arthur, ByteChallenges, ByteReader, ProofError, ProofResult,
};
use rand::{Rng, SeedableRng};

use crate::{
    fs_utils::EVMFs,
    parameters::FoldType,
    poly_utils::{coeffs::CoefficientList, eq_poly_outside, fold::compute_fold, MultilinearPoint},
    sumcheck::proof::SumcheckPolynomial,
    utils::{self, expand_randomness},
};

use super::{parameters::WhirConfig, Statement, WhirProof};

pub struct Verifier<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config,
{
    params: WhirConfig<F, MerkleConfig, PowStrategy>,
    two_inv: F,
}

#[derive(Clone)]
struct ParsedCommitment<F, D> {
    root: D,
    ood_points: Vec<F>,
    ood_answers: Vec<F>,
}

#[derive(Clone)]
struct ParsedProof<F> {
    initial_combination_randomness: Vec<F>,
    initial_sumcheck_rounds: Vec<(SumcheckPolynomial<F>, F)>,
    rounds: Vec<ParsedRound<F>>,
    final_domain_gen_inv: F,
    final_randomness_indexes: Vec<usize>,
    final_randomness_points: Vec<F>,
    final_randomness_answers: Vec<Vec<F>>,
    final_folding_randomness: MultilinearPoint<F>,
    final_sumcheck_rounds: Vec<(SumcheckPolynomial<F>, F)>,
    final_sumcheck_randomness: MultilinearPoint<F>,
    final_coefficients: CoefficientList<F>,
}

#[derive(Debug, Clone)]
struct ParsedRound<F> {
    folding_randomness: MultilinearPoint<F>,
    ood_points: Vec<F>,
    ood_answers: Vec<F>,
    stir_challenges_indexes: Vec<usize>,
    stir_challenges_points: Vec<F>,
    stir_challenges_answers: Vec<Vec<F>>,
    combination_randomness: Vec<F>,
    sumcheck_rounds: Vec<(SumcheckPolynomial<F>, F)>,
    domain_gen_inv: F,
}

impl<F, MerkleConfig, PowStrategy> Verifier<F, MerkleConfig, PowStrategy>
where
    F: FftField,
    MerkleConfig: Config<Leaf = [F]>,
    MerkleConfig::InnerDigest: AsRef<[u8]> + From<[u8; 32]>,
    PowStrategy: pow::PowStrategy,
{
    pub fn new(params: WhirConfig<F, MerkleConfig, PowStrategy>) -> Self {
        Verifier {
            params,
            two_inv: F::from(2).inverse().unwrap(), // The only inverse in the entire code :)
        }
    }

    fn evm_parse_commitment(
        &self,
        evmfs: &mut EVMFs<F>,
    ) -> ProofResult<ParsedCommitment<F, MerkleConfig::InnerDigest>> {
        // TODO: this is ugly :(
        let root: [u8; 32] = evmfs
            .next_bytes(32)
            .chunks_exact(32)
            .map(|c| <[u8; 32]>::try_from(c).unwrap())
            .collect::<Vec<[u8; 32]>>()[0];

        let mut ood_points = vec![F::ZERO; self.params.committment_ood_samples];
        let mut ood_answers = vec![F::ZERO; self.params.committment_ood_samples];
        if self.params.committment_ood_samples > 0 {
            ood_points = evmfs.squeeze_scalars(self.params.committment_ood_samples);
            ood_answers = evmfs.next_scalars(self.params.committment_ood_samples);
            //   arthur.fill_challenge_scalars(&mut ood_points)?;
            // arthur.fill_next_scalars(&mut ood_answers)?;
        }

        Ok(ParsedCommitment {
            root: root.into(),
            ood_points,
            ood_answers,
        })

        //Ok(ParsedCommitment {
        //    root: root.into(),
        //    ood_points,
        //    ood_answers,
        //})
    }

    fn parse_commitment(
        &self,
        arthur: &mut Arthur,
    ) -> ProofResult<ParsedCommitment<F, MerkleConfig::InnerDigest>> {
        let root: [u8; 32] = arthur.next_bytes()?;

        let mut ood_points = vec![F::ZERO; self.params.committment_ood_samples];
        let mut ood_answers = vec![F::ZERO; self.params.committment_ood_samples];
        if self.params.committment_ood_samples > 0 {
            arthur.fill_challenge_scalars(&mut ood_points)?;
            arthur.fill_next_scalars(&mut ood_answers)?;
        }

        Ok(ParsedCommitment {
            root: root.into(),
            ood_points,
            ood_answers,
        })
    }

    fn evm_parse_proof(
        &self,
        evmfs: &mut EVMFs<F>,
        parsed_commitment: &ParsedCommitment<F, MerkleConfig::InnerDigest>,
        statement: &Statement<F>, // Will be needed later
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<ParsedProof<F>> {
        // Derive combination randomness and first sumcheck polynomial
        let [combination_randomness_gen] = [evmfs.squeeze_scalars(1)[0]];

        // let [combination_randomness_gen]: [F; 1] = arthur.challenge_scalars()?;
        let initial_combination_randomness = expand_randomness(
            combination_randomness_gen,
            parsed_commitment.ood_points.len() + statement.points.len(),
        );

        // Initial sumcheck
        let mut sumcheck_rounds = Vec::with_capacity(self.params.folding_factor);
        for _ in 0..self.params.folding_factor {
            let sumcheck_poly_evals = evmfs.next_scalars(3);
            // let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = [evmfs.squeeze_scalars(1)[0]];
            // let [folding_randomness_single] = arthur.challenge_scalars()?;
            sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            // TODO: PoW
            //if self.params.starting_folding_pow_bits > 0. {
            //    arthur.challenge_pow::<PowStrategy>(self.params.starting_folding_pow_bits)?;
            //}
        }

        let mut folding_randomness =
            MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());

        let mut prev_root = parsed_commitment.root.clone();
        let domain_gen = self.params.starting_domain.backing_domain.group_gen();
        let mut exp_domain_gen = domain_gen.pow([1 << self.params.folding_factor]);
        let mut domain_gen_inv = self.params.starting_domain.backing_domain.group_gen_inv();
        let mut domain_size = self.params.starting_domain.size();
        let mut rounds = vec![];

        for r in 0..self.params.n_rounds() {
            let (merkle_proof, answers) = &whir_proof.0[r];
            let round_params = &self.params.round_parameters[r];

            let new_root: [u8; 32] = evmfs
                .next_bytes(32)
                .chunks_exact(32)
                .map(|c| <[u8; 32]>::try_from(c).unwrap())
                .collect::<Vec<[u8; 32]>>()[0];
            // let new_root: [u8; 32] = arthur.next_bytes()?;

            let mut ood_points = vec![F::ZERO; round_params.ood_samples];
            let mut ood_answers = vec![F::ZERO; round_params.ood_samples];
            if round_params.ood_samples > 0 {
                ood_points = evmfs.squeeze_scalars(round_params.ood_samples);
                ood_answers = evmfs.next_scalars(round_params.ood_samples);
                //   arthur.fill_challenge_scalars(&mut ood_points)?;
                // arthur.fill_next_scalars(&mut ood_answers)?;
            }

            // TODO: EVMFS: Replace the Chacha20Rng
            let mut stir_queries_seed = evmfs.squeeze_bytes(32)[0];
            //            let mut stir_queries_seed = [0u8; 32];
            //           arthur.fill_challenge_bytes(&mut stir_queries_seed)?;
            let mut stir_gen = rand_chacha::ChaCha20Rng::from_seed(stir_queries_seed);
            let folded_domain_size = domain_size / (1 << self.params.folding_factor);
            let stir_challenges_indexes = utils::dedup(
                (0..round_params.num_queries).map(|_| stir_gen.gen_range(0..folded_domain_size)),
            );
            let stir_challenges_points = stir_challenges_indexes
                .iter()
                .map(|index| exp_domain_gen.pow([*index as u64]))
                .collect();
            if !merkle_proof
                .verify(
                    &self.params.leaf_hash_params,
                    &self.params.two_to_one_params,
                    &prev_root,
                    answers.iter().map(|a| a.as_ref()),
                )
                .unwrap()
                || merkle_proof.leaf_indexes != stir_challenges_indexes
            {
                return Err(ProofError::InvalidProof);
            }

            // TODO: EVMFS PoW
            //if round_params.pow_bits > 0. {
            //   arthur.challenge_pow::<PowStrategy>(round_params.pow_bits)?;
            //}

            let [combination_randomness_gen] = [evmfs.squeeze_scalars(1)[0]];
            // let [combination_randomness_gen] = arthur.challenge_scalars()?;
            let combination_randomness = expand_randomness(
                combination_randomness_gen,
                stir_challenges_indexes.len() + round_params.ood_samples,
            );

            let mut sumcheck_rounds = Vec::with_capacity(self.params.folding_factor);
            for _ in 0..self.params.folding_factor {
                let sumcheck_poly_evals = evmfs.next_scalars(3);
                // let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let [folding_randomness_single] = [evmfs.squeeze_scalars(1)[0]];
                // let [folding_randomness_single] = arthur.challenge_scalars()?;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

                // TODO: EVMFS PoW
                //if round_params.folding_pow_bits > 0. {
                //    arthur.challenge_pow::<PowStrategy>(round_params.folding_pow_bits)?;
                //}
            }

            let new_folding_randomness =
                MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());

            rounds.push(ParsedRound {
                folding_randomness,
                ood_points,
                ood_answers,
                stir_challenges_indexes,
                stir_challenges_points,
                stir_challenges_answers: answers.to_vec(),
                combination_randomness,
                sumcheck_rounds,
                domain_gen_inv,
            });

            folding_randomness = new_folding_randomness;

            prev_root = new_root.into();
            exp_domain_gen = exp_domain_gen * exp_domain_gen;
            domain_gen_inv = domain_gen_inv * domain_gen_inv;
            domain_size /= 2;
        }

        let mut final_coefficients = evmfs.next_scalars(1 << self.params.final_sumcheck_rounds);
        //let mut final_coefficients = vec![F::ZERO; 1 << self.params.final_sumcheck_rounds];
        //arthur.fill_next_scalars(&mut final_coefficients)?;
        let final_coefficients = CoefficientList::new(final_coefficients);

        // Final queries verify
        let mut queries_seed = evmfs.squeeze_bytes(32)[0];
        //let mut queries_seed = [0u8; 32];
        //arthur.fill_challenge_bytes(&mut queries_seed)?;
        let mut final_gen = rand_chacha::ChaCha20Rng::from_seed(queries_seed);
        let folded_domain_size = domain_size / (1 << self.params.folding_factor);
        let final_randomness_indexes = utils::dedup(
            (0..self.params.final_queries).map(|_| final_gen.gen_range(0..folded_domain_size)),
        );
        let final_randomness_points = final_randomness_indexes
            .iter()
            .map(|index| exp_domain_gen.pow([*index as u64]))
            .collect();

        let (final_merkle_proof, final_randomness_answers) = &whir_proof.0[whir_proof.0.len() - 1];
        if !final_merkle_proof
            .verify(
                &self.params.leaf_hash_params,
                &self.params.two_to_one_params,
                &prev_root,
                final_randomness_answers.iter().map(|a| a.as_ref()),
            )
            .unwrap()
            || final_merkle_proof.leaf_indexes != final_randomness_indexes
        {
            return Err(ProofError::InvalidProof);
        }

        // TODO: EVMFS Pow
        //if self.params.final_pow_bits > 0. {
        //    arthur.challenge_pow::<PowStrategy>(self.params.final_pow_bits)?;
        //}

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals = evmfs.next_scalars(3);
            //let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = [evmfs.squeeze_scalars(1)[0]];
            // let [folding_randomness_single] = arthur.challenge_scalars()?;
            final_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            // TODO: EVMFS PoW
            //if self.params.final_folding_pow_bits > 0. {
            //    arthur.challenge_pow::<PowStrategy>(self.params.final_folding_pow_bits)?;
            //}
        }
        let final_sumcheck_randomness = MultilinearPoint(
            final_sumcheck_rounds
                .iter()
                .map(|&(_, r)| r)
                .rev()
                .collect(),
        );

        Ok(ParsedProof {
            initial_combination_randomness,
            initial_sumcheck_rounds: sumcheck_rounds,
            rounds,
            final_domain_gen_inv: domain_gen_inv,
            final_folding_randomness: folding_randomness,
            final_randomness_indexes,
            final_randomness_points,
            final_randomness_answers: final_randomness_answers.to_vec(),
            final_sumcheck_rounds,
            final_sumcheck_randomness,
            final_coefficients,
        })
    }

    fn parse_proof(
        &self,
        arthur: &mut Arthur,
        parsed_commitment: &ParsedCommitment<F, MerkleConfig::InnerDigest>,
        statement: &Statement<F>, // Will be needed later
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<ParsedProof<F>> {
        // Derive combination randomness and first sumcheck polynomial
        let [combination_randomness_gen]: [F; 1] = arthur.challenge_scalars()?;
        let initial_combination_randomness = expand_randomness(
            combination_randomness_gen,
            parsed_commitment.ood_points.len() + statement.points.len(),
        );

        // Initial sumcheck
        let mut sumcheck_rounds = Vec::with_capacity(self.params.folding_factor);
        for _ in 0..self.params.folding_factor {
            let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = arthur.challenge_scalars()?;
            sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            if self.params.starting_folding_pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(self.params.starting_folding_pow_bits)?;
            }
        }

        let mut folding_randomness =
            MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());

        let mut prev_root = parsed_commitment.root.clone();
        let domain_gen = self.params.starting_domain.backing_domain.group_gen();
        let mut exp_domain_gen = domain_gen.pow([1 << self.params.folding_factor]);
        let mut domain_gen_inv = self.params.starting_domain.backing_domain.group_gen_inv();
        let mut domain_size = self.params.starting_domain.size();
        let mut rounds = vec![];

        for r in 0..self.params.n_rounds() {
            let (merkle_proof, answers) = &whir_proof.0[r];
            let round_params = &self.params.round_parameters[r];

            let new_root: [u8; 32] = arthur.next_bytes()?;

            let mut ood_points = vec![F::ZERO; round_params.ood_samples];
            let mut ood_answers = vec![F::ZERO; round_params.ood_samples];
            if round_params.ood_samples > 0 {
                arthur.fill_challenge_scalars(&mut ood_points)?;
                arthur.fill_next_scalars(&mut ood_answers)?;
            }

            let mut stir_queries_seed = [0u8; 32];
            arthur.fill_challenge_bytes(&mut stir_queries_seed)?;
            let mut stir_gen = rand_chacha::ChaCha20Rng::from_seed(stir_queries_seed);
            let folded_domain_size = domain_size / (1 << self.params.folding_factor);
            let stir_challenges_indexes = utils::dedup(
                (0..round_params.num_queries).map(|_| stir_gen.gen_range(0..folded_domain_size)),
            );
            let stir_challenges_points = stir_challenges_indexes
                .iter()
                .map(|index| exp_domain_gen.pow([*index as u64]))
                .collect();

            if !merkle_proof
                .verify(
                    &self.params.leaf_hash_params,
                    &self.params.two_to_one_params,
                    &prev_root,
                    answers.iter().map(|a| a.as_ref()),
                )
                .unwrap()
                || merkle_proof.leaf_indexes != stir_challenges_indexes
            {
                return Err(ProofError::InvalidProof);
            }

            if round_params.pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(round_params.pow_bits)?;
            }

            let [combination_randomness_gen] = arthur.challenge_scalars()?;
            let combination_randomness = expand_randomness(
                combination_randomness_gen,
                stir_challenges_indexes.len() + round_params.ood_samples,
            );

            let mut sumcheck_rounds = Vec::with_capacity(self.params.folding_factor);
            for _ in 0..self.params.folding_factor {
                let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
                let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
                let [folding_randomness_single] = arthur.challenge_scalars()?;
                sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

                if round_params.folding_pow_bits > 0. {
                    arthur.challenge_pow::<PowStrategy>(round_params.folding_pow_bits)?;
                }
            }

            let new_folding_randomness =
                MultilinearPoint(sumcheck_rounds.iter().map(|&(_, r)| r).rev().collect());

            rounds.push(ParsedRound {
                folding_randomness,
                ood_points,
                ood_answers,
                stir_challenges_indexes,
                stir_challenges_points,
                stir_challenges_answers: answers.to_vec(),
                combination_randomness,
                sumcheck_rounds,
                domain_gen_inv,
            });

            folding_randomness = new_folding_randomness;

            prev_root = new_root.into();
            exp_domain_gen = exp_domain_gen * exp_domain_gen;
            domain_gen_inv = domain_gen_inv * domain_gen_inv;
            domain_size /= 2;
        }

        let mut final_coefficients = vec![F::ZERO; 1 << self.params.final_sumcheck_rounds];
        arthur.fill_next_scalars(&mut final_coefficients)?;
        let final_coefficients = CoefficientList::new(final_coefficients);

        // Final queries verify
        let mut queries_seed = [0u8; 32];
        arthur.fill_challenge_bytes(&mut queries_seed)?;
        let mut final_gen = rand_chacha::ChaCha20Rng::from_seed(queries_seed);
        let folded_domain_size = domain_size / (1 << self.params.folding_factor);
        let final_randomness_indexes = utils::dedup(
            (0..self.params.final_queries).map(|_| final_gen.gen_range(0..folded_domain_size)),
        );
        let final_randomness_points = final_randomness_indexes
            .iter()
            .map(|index| exp_domain_gen.pow([*index as u64]))
            .collect();

        let (final_merkle_proof, final_randomness_answers) = &whir_proof.0[whir_proof.0.len() - 1];
        if !final_merkle_proof
            .verify(
                &self.params.leaf_hash_params,
                &self.params.two_to_one_params,
                &prev_root,
                final_randomness_answers.iter().map(|a| a.as_ref()),
            )
            .unwrap()
            || final_merkle_proof.leaf_indexes != final_randomness_indexes
        {
            return Err(ProofError::InvalidProof);
        }

        if self.params.final_pow_bits > 0. {
            arthur.challenge_pow::<PowStrategy>(self.params.final_pow_bits)?;
        }

        let mut final_sumcheck_rounds = Vec::with_capacity(self.params.final_sumcheck_rounds);
        for _ in 0..self.params.final_sumcheck_rounds {
            let sumcheck_poly_evals: [F; 3] = arthur.next_scalars()?;
            let sumcheck_poly = SumcheckPolynomial::new(sumcheck_poly_evals.to_vec(), 1);
            let [folding_randomness_single] = arthur.challenge_scalars()?;
            final_sumcheck_rounds.push((sumcheck_poly, folding_randomness_single));

            if self.params.final_folding_pow_bits > 0. {
                arthur.challenge_pow::<PowStrategy>(self.params.final_folding_pow_bits)?;
            }
        }
        let final_sumcheck_randomness = MultilinearPoint(
            final_sumcheck_rounds
                .iter()
                .map(|&(_, r)| r)
                .rev()
                .collect(),
        );

        Ok(ParsedProof {
            initial_combination_randomness,
            initial_sumcheck_rounds: sumcheck_rounds,
            rounds,
            final_domain_gen_inv: domain_gen_inv,
            final_folding_randomness: folding_randomness,
            final_randomness_indexes,
            final_randomness_points,
            final_randomness_answers: final_randomness_answers.to_vec(),
            final_sumcheck_rounds,
            final_sumcheck_randomness,
            final_coefficients,
        })
    }

    fn compute_v_poly(
        &self,
        parsed_commitment: &ParsedCommitment<F, MerkleConfig::InnerDigest>,
        statement: &Statement<F>,
        proof: &ParsedProof<F>,
    ) -> F {
        let mut num_variables = self.params.mv_parameters.num_variables;

        let mut folding_randomness = MultilinearPoint(
            iter::once(&proof.final_sumcheck_randomness.0)
                .chain(iter::once(&proof.final_folding_randomness.0))
                .chain(proof.rounds.iter().rev().map(|r| &r.folding_randomness.0))
                .flatten()
                .copied()
                .collect(),
        );

        let mut value = parsed_commitment
            .ood_points
            .iter()
            .map(|ood_point| MultilinearPoint::expand_from_univariate(*ood_point, num_variables))
            .chain(statement.points.clone())
            .zip(&proof.initial_combination_randomness)
            .map(|(point, randomness)| *randomness * eq_poly_outside(&point, &folding_randomness))
            .sum();

        for round_proof in &proof.rounds {
            num_variables -= self.params.folding_factor;
            folding_randomness = MultilinearPoint(folding_randomness.0[..num_variables].to_vec());

            let ood_points = &round_proof.ood_points;
            let stir_challenges_points = &round_proof.stir_challenges_points;
            let stir_challenges: Vec<_> = ood_points
                .iter()
                .chain(stir_challenges_points)
                .cloned()
                .map(|univariate| {
                    MultilinearPoint::expand_from_univariate(univariate, num_variables)
                    // TODO:
                    // Maybe refactor outside
                })
                .collect();

            let sum_of_claims: F = stir_challenges
                .into_iter()
                .map(|point| eq_poly_outside(&point, &folding_randomness))
                .zip(&round_proof.combination_randomness)
                .map(|(point, rand)| point * rand)
                .sum();

            value = value + sum_of_claims;
        }

        value
    }

    fn compute_folds(&self, parsed: &ParsedProof<F>) -> Vec<Vec<F>> {
        match self.params.fold_optimisation {
            FoldType::Naive => self.compute_folds_full(parsed),
            FoldType::ProverHelps => self.compute_folds_helped(parsed),
        }
    }

    fn compute_folds_full(&self, parsed: &ParsedProof<F>) -> Vec<Vec<F>> {
        let mut domain_size = self.params.starting_domain.backing_domain.size();
        let coset_domain_size = 1 << self.params.folding_factor;

        let mut result = Vec::new();

        for round in &parsed.rounds {
            // This is such that coset_generator^coset_domain_size = F::ONE
            //let _coset_generator = domain_gen.pow(&[(domain_size / coset_domain_size) as u64]);
            let coset_generator_inv = round
                .domain_gen_inv
                .pow([(domain_size / coset_domain_size) as u64]);

            let evaluations: Vec<_> = round
                .stir_challenges_indexes
                .iter()
                .zip(&round.stir_challenges_answers)
                .map(|(index, answers)| {
                    // The coset is w^index * <w_coset_generator>
                    //let _coset_offset = domain_gen.pow(&[*index as u64]);
                    let coset_offset_inv = round.domain_gen_inv.pow([*index as u64]);

                    compute_fold(
                        answers,
                        &round.folding_randomness.0,
                        coset_offset_inv,
                        coset_generator_inv,
                        self.two_inv,
                        self.params.folding_factor,
                    )
                })
                .collect();
            result.push(evaluations);
            domain_size /= 2;
        }

        let domain_gen_inv = parsed.final_domain_gen_inv;

        // Final round
        let coset_generator_inv = domain_gen_inv.pow([(domain_size / coset_domain_size) as u64]);
        let evaluations: Vec<_> = parsed
            .final_randomness_indexes
            .iter()
            .zip(&parsed.final_randomness_answers)
            .map(|(index, answers)| {
                // The coset is w^index * <w_coset_generator>
                //let _coset_offset = domain_gen.pow(&[*index as u64]);
                let coset_offset_inv = domain_gen_inv.pow([*index as u64]);

                compute_fold(
                    answers,
                    &parsed.final_folding_randomness.0,
                    coset_offset_inv,
                    coset_generator_inv,
                    self.two_inv,
                    self.params.folding_factor,
                )
            })
            .collect();
        result.push(evaluations);

        result
    }

    fn compute_folds_helped(&self, parsed: &ParsedProof<F>) -> Vec<Vec<F>> {
        let mut result = Vec::new();

        for round in &parsed.rounds {
            let evaluations: Vec<_> = round
                .stir_challenges_answers
                .iter()
                .map(|answers| {
                    CoefficientList::new(answers.to_vec()).evaluate(&round.folding_randomness)
                })
                .collect();
            result.push(evaluations);
        }

        // Final round
        let evaluations: Vec<_> = parsed
            .final_randomness_answers
            .iter()
            .map(|answers| {
                CoefficientList::new(answers.to_vec()).evaluate(&parsed.final_folding_randomness)
            })
            .collect();
        result.push(evaluations);

        result
    }

    pub fn evm_verify(
        &self,
        evmfs: &mut EVMFs<F>,
        statement: &Statement<F>,
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<()> {
        // We first do a pass in which we rederive all the FS challenges
        // Then we will check the algebraic part (so to optimise inversions)
        let parsed_commitment = self.evm_parse_commitment(evmfs)?;
        let parsed = self.evm_parse_proof(evmfs, &parsed_commitment, statement, whir_proof)?;

        let computed_folds = self.compute_folds(&parsed);

        // Check the first polynomial
        let (mut prev_poly, mut randomness) = parsed.initial_sumcheck_rounds[0].clone();
        if prev_poly.sum_over_hypercube()
            != parsed_commitment
                .ood_answers
                .iter()
                .copied()
                .chain(statement.evaluations.clone())
                .zip(&parsed.initial_combination_randomness)
                .map(|(ans, rand)| ans * rand)
                .sum()
        {
            return Err(ProofError::InvalidProof);
        }

        // Check the rest of the rounds
        for (sumcheck_poly, new_randomness) in &parsed.initial_sumcheck_rounds[1..] {
            if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&randomness.into())
            {
                return Err(ProofError::InvalidProof);
            }
            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;
        }

        for (round, folds) in parsed.rounds.iter().zip(&computed_folds) {
            let (sumcheck_poly, new_randomness) = &round.sumcheck_rounds[0].clone();

            let values = round.ood_answers.iter().copied().chain(folds.clone());

            let claimed_sum = prev_poly.evaluate_at_point(&randomness.into())
                + values
                    .zip(&round.combination_randomness)
                    .map(|(val, rand)| val * rand)
                    .sum::<F>();

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }
        }

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations = parsed
            .final_coefficients
            .evaluate_at_univariate(&parsed.final_randomness_points);
        if !final_folds
            .iter()
            .zip(final_evaluations)
            .all(|(&fold, eval)| fold == eval)
        {
            return Err(ProofError::InvalidProof);
        }

        // Check the final sumchecks
        if self.params.final_sumcheck_rounds > 0 {
            let (sumcheck_poly, new_randomness) = &parsed.final_sumcheck_rounds[0].clone();
            let claimed_sum = prev_poly.evaluate_at_point(&randomness.into());

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &parsed.final_sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }
        }

        // Check the final sumcheck evaluation
        let evaluation_of_v_poly = self.compute_v_poly(&parsed_commitment, statement, &parsed);

        if prev_poly.evaluate_at_point(&randomness.into())
            != evaluation_of_v_poly
                * parsed
                    .final_coefficients
                    .evaluate(&parsed.final_sumcheck_randomness)
        {
            return Err(ProofError::InvalidProof);
        }

        Ok(())
    }

    pub fn verify(
        &self,
        arthur: &mut Arthur,
        statement: &Statement<F>,
        whir_proof: &WhirProof<MerkleConfig, F>,
    ) -> ProofResult<()> {
        // We first do a pass in which we rederive all the FS challenges
        // Then we will check the algebraic part (so to optimise inversions)
        let parsed_commitment = self.parse_commitment(arthur)?;
        let parsed = self.parse_proof(arthur, &parsed_commitment, statement, whir_proof)?;

        let computed_folds = self.compute_folds(&parsed);

        // Check the first polynomial
        let (mut prev_poly, mut randomness) = parsed.initial_sumcheck_rounds[0].clone();
        if prev_poly.sum_over_hypercube()
            != parsed_commitment
                .ood_answers
                .iter()
                .copied()
                .chain(statement.evaluations.clone())
                .zip(&parsed.initial_combination_randomness)
                .map(|(ans, rand)| ans * rand)
                .sum()
        {
            return Err(ProofError::InvalidProof);
        }

        // Check the rest of the rounds
        for (sumcheck_poly, new_randomness) in &parsed.initial_sumcheck_rounds[1..] {
            if sumcheck_poly.sum_over_hypercube() != prev_poly.evaluate_at_point(&randomness.into())
            {
                return Err(ProofError::InvalidProof);
            }
            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;
        }

        for (round, folds) in parsed.rounds.iter().zip(&computed_folds) {
            let (sumcheck_poly, new_randomness) = &round.sumcheck_rounds[0].clone();

            let values = round.ood_answers.iter().copied().chain(folds.clone());

            let claimed_sum = prev_poly.evaluate_at_point(&randomness.into())
                + values
                    .zip(&round.combination_randomness)
                    .map(|(val, rand)| val * rand)
                    .sum::<F>();

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &round.sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }
        }

        // Check the foldings computed from the proof match the evaluations of the polynomial
        let final_folds = &computed_folds[computed_folds.len() - 1];
        let final_evaluations = parsed
            .final_coefficients
            .evaluate_at_univariate(&parsed.final_randomness_points);
        if !final_folds
            .iter()
            .zip(final_evaluations)
            .all(|(&fold, eval)| fold == eval)
        {
            return Err(ProofError::InvalidProof);
        }

        // Check the final sumchecks
        if self.params.final_sumcheck_rounds > 0 {
            let (sumcheck_poly, new_randomness) = &parsed.final_sumcheck_rounds[0].clone();
            let claimed_sum = prev_poly.evaluate_at_point(&randomness.into());

            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(ProofError::InvalidProof);
            }

            prev_poly = sumcheck_poly.clone();
            randomness = *new_randomness;

            // Check the rest of the round
            for (sumcheck_poly, new_randomness) in &parsed.final_sumcheck_rounds[1..] {
                if sumcheck_poly.sum_over_hypercube()
                    != prev_poly.evaluate_at_point(&randomness.into())
                {
                    return Err(ProofError::InvalidProof);
                }
                prev_poly = sumcheck_poly.clone();
                randomness = *new_randomness;
            }
        }

        // Check the final sumcheck evaluation
        let evaluation_of_v_poly = self.compute_v_poly(&parsed_commitment, statement, &parsed);

        if prev_poly.evaluate_at_point(&randomness.into())
            != evaluation_of_v_poly
                * parsed
                    .final_coefficients
                    .evaluate(&parsed.final_sumcheck_randomness)
        {
            return Err(ProofError::InvalidProof);
        }

        Ok(())
    }
}
