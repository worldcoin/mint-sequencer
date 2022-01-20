use crate::{
    ethereum::{self, BLSPubKey, CommitmentProof, Ethereum},
    hubble::{self, Hubble},
    server::Error as ServerError,
};
use ethers::prelude::{H256, U256};
use eyre::Result as EyreResult;
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
}
