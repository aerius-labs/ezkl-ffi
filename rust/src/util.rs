use ezkl::circuit::CheckMode;
use ezkl::{Commitments, pfsys};
use ezkl::graph::{GraphCircuit, GraphSettings, GraphWitness};
use ezkl::pfsys::{create_proof_circuit, TranscriptType, verify_proof_circuit};
use ezkl::pfsys::evm::aggregation_kzg::PoseidonTranscript;
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{ParamsProver};
use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_proofs::poly::ipa::{
    commitment::{IPACommitmentScheme, ParamsIPA},
    strategy::SingleStrategy as IPASingleStrategy,
};
use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::kzg::{
    commitment::{KZGCommitmentScheme, ParamsKZG},
    strategy::SingleStrategy as KZGSingleStrategy,
};
use halo2_proofs::poly::VerificationStrategy;
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::loader::native::NativeLoader;

use anyhow::{ Result, Error};

pub(crate) fn prove(
    witness: Vec<u8>,
    pk: Vec<u8>,
    compiled_circuit: Vec<u8>,
    srs: Vec<u8>,
) -> Result<Vec<u8>> {

    // read in circuit
    let mut circuit: GraphCircuit = bincode::deserialize(&compiled_circuit[..])
        .map_err(|e| Error::msg(format!("Failed to deserialize circuit: {}", e)))?;

    // read in model input
    let data: GraphWitness = serde_json::from_slice(&witness[..])
        .map_err(|e| Error::msg(format!("Failed to deserialize witness: {}", e)))?;

    // read in proving key
    let mut reader = std::io::BufReader::new(&pk[..]);
    let pk = ProvingKey::<G1Affine>::read::<_, GraphCircuit>(
        &mut reader,
        halo2_proofs::SerdeFormat::RawBytes,
        circuit.settings().clone(),
    )
        .map_err(|e| Error::msg(format!("Failed to deserialize proving key: {}", e)))?;

    // prep public inputs
    circuit
        .load_graph_witness(&data)
        .map_err(|e| Error::msg(format!("{}", e)))?;
    let public_inputs = circuit
        .prepare_public_inputs(&data)
        .map_err(|e| Error::msg(format!("{}", e)))?;
    let proof_split_commits: Option<pfsys::ProofSplitCommit> = data.into();

    // read in kzg params
    let mut reader = std::io::BufReader::new(&srs[..]);
    let commitment = circuit.settings().run_args.commitment.into();
    // creates and verifies the proof
    let proof = match commitment {
        Commitments::KZG => {
            let params: ParamsKZG<Bn256> =
                halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader)
                    .map_err(|e| Error::msg(format!("Failed to deserialize srs: {}", e)))?;

            create_proof_circuit::<
                KZGCommitmentScheme<Bn256>,
                _,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                KZGSingleStrategy<_>,
                _,
                EvmTranscript<_, _, _, _>,
                EvmTranscript<_, _, _, _>,
            >(
                circuit,
                vec![public_inputs],
                &params,
                &pk,
                CheckMode::UNSAFE,
                Commitments::KZG,
                TranscriptType::EVM,
                proof_split_commits,
                None,
            )
        }
        Commitments::IPA => {
            let params: ParamsIPA<_> =
                halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader)
                    .map_err(|e| Error::msg(format!("Failed to deserialize srs: {}", e)))?;

            create_proof_circuit::<
                IPACommitmentScheme<G1Affine>,
                _,
                ProverIPA<_>,
                VerifierIPA<_>,
                IPASingleStrategy<_>,
                _,
                EvmTranscript<_, _, _, _>,
                EvmTranscript<_, _, _, _>,
            >(
                circuit,
                vec![public_inputs],
                &params,
                &pk,
                CheckMode::UNSAFE,
                Commitments::IPA,
                TranscriptType::EVM,
                proof_split_commits,
                None,
            )
        }
    }
        .map_err(|e| Error::msg(format!("{}", e)))?;

    Ok(serde_json::to_string(&proof)
        .map_err(|e| Error::msg(format!("{}", e)))?
        .into_bytes())
}

pub(crate) fn verify(
    proof_js: Vec<u8>,
    vk: Vec<u8>,
    settings: Vec<u8>,
    srs: Vec<u8>,
) -> Result<bool> {
    let circuit_settings: GraphSettings = serde_json::from_slice(&settings[..])
        .map_err(|e| Error::msg(format!("Failed to deserialize settings: {}", e)))?;

    let proof: pfsys::Snark<Fr, G1Affine> = serde_json::from_slice(&proof_js[..])
        .map_err(|e| Error::msg(format!("Failed to deserialize proof: {}", e)))?;

    let mut reader = std::io::BufReader::new(&vk[..]);
    let vk = VerifyingKey::<G1Affine>::read::<_, GraphCircuit>(
        &mut reader,
        halo2_proofs::SerdeFormat::RawBytes,
        circuit_settings.clone(),
    )
        .map_err(|e| Error::msg(format!("Failed to deserialize vk: {}", e)))?;

    let orig_n = 1 << circuit_settings.run_args.logrows;

    let commitment = circuit_settings.run_args.commitment.into();

    let mut reader = std::io::BufReader::new(&srs[..]);
    let result = match commitment {
        Commitments::KZG => {
            let params: ParamsKZG<Bn256> =
                halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader)
                    .map_err(|e| Error::msg(format!("Failed to deserialize params: {}", e)))?;
            let strategy = KZGSingleStrategy::new(params.verifier_params());
            match proof.transcript_type {
                TranscriptType::EVM => verify_proof_circuit::<
                    VerifierSHPLONK<'_, Bn256>,
                    KZGCommitmentScheme<Bn256>,
                    KZGSingleStrategy<_>,
                    _,
                    EvmTranscript<G1Affine, _, _, _>,
                >(&proof, &params, &vk, strategy, orig_n),

                TranscriptType::Poseidon => {
                    verify_proof_circuit::<
                        VerifierSHPLONK<'_, Bn256>,
                        KZGCommitmentScheme<Bn256>,
                        KZGSingleStrategy<_>,
                        _,
                        PoseidonTranscript<NativeLoader, _>,
                    >(&proof, &params, &vk, strategy, orig_n)
                }
            }
        }
        Commitments::IPA => {
            let params: ParamsIPA<_> =
                halo2_proofs::poly::commitment::Params::<'_, G1Affine>::read(&mut reader)
                    .map_err(|e| Error::msg(format!("Failed to deserialize params: {}", e)))?;
            let strategy = IPASingleStrategy::new(params.verifier_params());
            match proof.transcript_type {
                TranscriptType::EVM => verify_proof_circuit::<
                    VerifierIPA<_>,
                    IPACommitmentScheme<G1Affine>,
                    IPASingleStrategy<_>,
                    _,
                    EvmTranscript<G1Affine, _, _, _>,
                >(&proof, &params, &vk, strategy, orig_n),
                TranscriptType::Poseidon => {
                    verify_proof_circuit::<
                        VerifierIPA<_>,
                        IPACommitmentScheme<G1Affine>,
                        IPASingleStrategy<_>,
                        _,
                        PoseidonTranscript<NativeLoader, _>,
                    >(&proof, &params, &vk, strategy, orig_n)
                }
            }
        }
    };

    match result {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::msg(format!("{}", e))),
    }
}