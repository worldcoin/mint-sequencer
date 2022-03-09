use crate::{
    ethereum::{self, BLSPubKey, CommitmentProof, Ethereum},
    hubble::{self, Hubble},
    server::Error as ServerError,
};
use ethers::prelude::{Bytes, H256, U256};
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
        _external_nullifier: U256,
        _signal: &Bytes,
        _nullifier_hash: U256,
        _proof: CommitmentProof,
    ) -> Result<bool, ServerError> {
        let id = Identity::new(b"secret");

        const LEAF: Hash = Hash::from_bytes_be([0u8; 32]);

        let mut tree = PoseidonTree::new(21, LEAF);
        let (_, leaf) = id.commitment().to_bytes_be();
        tree.set(0, leaf.into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root();

        // change signal and external_nullifier here
        let signal = "xxx".as_bytes();
        let external_nullifier = "appId".as_bytes();

        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier);

        let proof =
            generate_proof(&self.config, &id, &merkle_proof, external_nullifier, signal).unwrap();

        let success = verify_proof(
            &self.config,
            &root.into(),
            &nullifier_hash,
            signal,
            external_nullifier,
            &proof,
        )
        .unwrap();

        // verify_proof(
        //     &self.config,
        //     root.into(),
        //     nullifier_hash,
        //     signal,
        //     external_nullifier,
        //     proof,
        // );

        Ok(success)
    }
}
