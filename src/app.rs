use crate::{
    ethereum::{self, BLSPubKey, CommitmentProof, Ethereum},
    hubble::{self, Hubble},
    server::Error as ServerError,
};
use ethers::{prelude::{Bytes, H256, U256}, utils::keccak256};
use eyre::Result as EyreResult;
use semaphore::{protocol::{SnarkFileConfig, verify_proof, generate_nullifier_hash, generate_proof}, hash::Hash, poseidon_tree::PoseidonTree, identity::Identity};
use structopt::StructOpt;

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    #[structopt(flatten)]
    pub ethereum: ethereum::Options,

    #[structopt(flatten)]
    hubble: hubble::Options,
}

#[allow(dead_code)]
pub struct App {
    ethereum: Ethereum,
    hubble:   Hubble,
    config: SnarkFileConfig,
}

impl App {
    /// # Errors
    ///
    /// Will return `Err` if the internal Ethereum handler errors
    pub async fn new(options: Options) -> EyreResult<Self> {
        let ethereum = Ethereum::new(options.ethereum).await?;
        let hubble = Hubble::new(options.hubble).await?;
        let config = SnarkFileConfig {
            zkey: "./semaphore/build/snark/semaphore_final.zkey".to_string(),
            wasm: "./semaphore/build/snark/semaphore.wasm".to_string(),
        };

        Ok(Self { ethereum, hubble, config })
    }

    /// # Errors
    pub async fn send_create_to_transfer(
        &self,
        pub_key: &BLSPubKey,
    ) -> Result<String, ServerError> {
        let tx_hash = self.hubble.send_create_to_transfer(pub_key).await?;
        Ok(tx_hash)
    }

    /// # Errors
    pub async fn submit_proof(
        &self,
        _group_id: usize,
        pub_key: &BLSPubKey,
        proof: CommitmentProof,
        nullifiers_hash: U256,
        tx_hash: &H256,
    ) -> Result<(), ServerError> {
        let root = self.ethereum.root().await?;
        let proof_valid = self
            .ethereum
            .pre_broadcast_check(pub_key, root, proof, nullifiers_hash)
            .await?;
        println!("Proof valid {}", proof_valid);
        let commitment_details = self.hubble.get_transfer_data(tx_hash).await?;

        self.ethereum
            .commit(pub_key, root, proof, nullifiers_hash, commitment_details)
            .await?;

        Ok(())
    }

    /// # Errors
    pub async fn signal(
        &self,
        _group_id: usize,
        external_nullifier: U256,
        signal: U256,
        nullifier_hash: Hash,
        _proof: CommitmentProof,
    ) -> Result<bool, ServerError> {
        let id = Identity::new(b"secret");

        const LEAF: Hash = Hash::from_bytes_be([0u8; 32]);

        let mut tree = PoseidonTree::new(21, LEAF);
        let (_, leaf) = id.commitment().to_bytes_be();
        tree.set(0, leaf.into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root();

        let signal_bytes: &mut [u8] = &mut [0; 32];
        signal.to_big_endian(signal_bytes);

        let external_nullifier_bytes: &mut [u8] = &mut [0; 32];
        external_nullifier.to_big_endian(external_nullifier_bytes);

        // TODO: semaphore-rs throwing some error related to regalloc
        let proof =
            generate_proof(&self.config, &id, &merkle_proof, external_nullifier_bytes, signal_bytes).unwrap();

        // let proof: Bn<Parameters> = _proof.map(|x| x.into());

        let success = verify_proof(
            &self.config,
            &root.into(),
            &nullifier_hash.into(),
            signal_bytes,
            external_nullifier_bytes,
            &proof,
        )
        .unwrap();
        Ok(true)

        // verify_proof(
        //     &self.config,
        //     root.into(),
        //     nullifier_hash,
        //     signal,
        //     external_nullifier_bytes,
        //     proof,
        // );

        // Ok(success)
    }
}
