use crate::{
    ethereum::{self, BLSPubKey, CommitmentProof, Ethereum},
    hubble::{self, Hubble},
    server::Error as ServerError,
};
use ethers::{prelude::{Bytes, H256, U256}, utils::keccak256};
use eyre::Result as EyreResult;
use semaphore::{protocol::{verify_proof, generate_nullifier_hash, generate_proof, hash_external_nullifier}, hash::Hash, poseidon_tree::PoseidonTree, identity::Identity};
use structopt::StructOpt;
use num_bigint::{BigInt, Sign};
use hex_literal::hex;

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
}

impl App {
    /// # Errors
    ///
    /// Will return `Err` if the internal Ethereum handler errors
    pub async fn new(options: Options) -> EyreResult<Self> {
        let ethereum = Ethereum::new(options.ethereum).await?;
        let hubble = Hubble::new(options.hubble).await?;

        Ok(Self { ethereum, hubble })
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
        proof: CommitmentProof,
    ) -> Result<bool, ServerError> {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // generate identity
        let id = Identity::new(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, LEAF);
        tree.set(0, id.commitment().into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root().into();

        let external_nullifier_bytes: &mut [u8] = &mut [0; 32];
        external_nullifier.to_big_endian(external_nullifier_bytes);

        let external_nullifier_hash = hash_external_nullifier(external_nullifier_bytes);


        let signal_bytes: &mut [u8] = &mut [0; 32];
        signal.to_big_endian(signal_bytes);


        // TODO
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let external_nullifier_hash = hash_external_nullifier(external_nullifier_bytes);

        // TODO remove
        let proof = generate_proof(&id, &merkle_proof, external_nullifier_bytes, signal_bytes).unwrap();
        println!("Proof {:?}", proof);


        let success =
            verify_proof(root, nullifier_hash, signal_bytes, external_nullifier_bytes, &proof).unwrap();

        assert!(success);
        println!("Success {}", success);
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
