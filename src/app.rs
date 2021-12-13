use crate::{
    ethereum::{self, Ethereum},
    server::Error as ServerError,
};
use ethers::prelude::U256;
use eyre::Result as EyreResult;
use structopt::StructOpt;

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    #[structopt(flatten)]
    pub ethereum: ethereum::Options,
}

#[allow(dead_code)]
pub struct App {
    ethereum: Ethereum,
}

impl App {
    /// # Errors
    ///
    /// Will return `Err` if the internal Ethereum handler errors
    pub async fn new(options: Options) -> EyreResult<Self> {
        let ethereum = Ethereum::new(options.ethereum).await?;

        Ok(Self { ethereum })
    }

    /// # Errors
    pub async fn submit_proof(
        &self,
        pub_key: String,
        proof: [U256; 8],
        nullifiers_hash: U256,
    ) -> Result<(), ServerError> {
        let root = self.ethereum.root().await?;
        let proof_valid = self
            .ethereum
            .pre_broadcast_check(pub_key, root, proof, nullifiers_hash)
            .await?;
        println!("Proof valid {}", proof_valid);
        Ok(())
    }
}
