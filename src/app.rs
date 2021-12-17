use crate::ethereum::{self, Ethereum};
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
}
