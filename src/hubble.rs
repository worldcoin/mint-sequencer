use ethers::prelude::U256;
use eyre::{Result as EyreResult, bail};
use hyper::{Client, client::HttpConnector, Method, Request, header, body::Buf};
use serde::{Serialize, Deserialize};
use serde_json::{Value, json, from_str};
use structopt::StructOpt;

use crate::server::Error;

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    #[structopt(long, env, default_value = "http://localhost:8080")]
    commander_uri: hyper::Uri,

    #[structopt(long, env, default_value = "50")]
    airdrop_amount: u32,

    #[structopt(long, env, default_value = "2")]
    from_state_id: u32,
}

pub struct Hubble {
    client: Client<HttpConnector>,
    commander_uri: hyper::Uri,
    airdrop_amount: u32,
    from_state_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentDetails {
    pub batch_id: U256,
    pub commitment_idx: U256,
    pub transfer_idx: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserState {
    #[serde(rename="StateID")]
    state_id: u32,
    #[serde(rename="PubKeyID")]
    pub_key_id: u32,
    #[serde(rename="TokenID")]
    token_id: String,
    #[serde(rename="Balance")]
    balance: U256,
    #[serde(rename="Nonce")]
    nonce: String,
}

impl Hubble {
    pub async fn new(options: Options) -> EyreResult<Self> {
        let client = Client::new();
        Ok(Hubble {
            client,
            commander_uri: options.commander_uri,
            airdrop_amount: options.airdrop_amount,
            from_state_id: options.from_state_id,
        })
    }

    pub async fn get_user_state(&self, state_id: u32) -> EyreResult<UserState> {
        let body = json!({
                "jsonrpc": "2.0",
                "method": "hubble_getUserState",
                "params": [
                    state_id
                ],
                "id": 1u32,
            }
        );
        println!("Body {}", body.to_string());

        let req = Request::builder()
            .method(Method::POST)
            .uri(self.commander_uri.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string().into())
            ?;

        let res = self.client.request(req).await?;

        // asynchronously aggregate the chunks of the body
        let body = hyper::body::aggregate(res).await?;

        // try to parse as json with serde_json
        let tx_result: Value = serde_json::from_reader(body.reader())?;

        let user_state = tx_result.get("result").ok_or(Error::HubbleError)?;
        let user_state = from_str::<UserState>(&user_state.to_string())?;
        println!("User state {:?}", user_state);
        Ok(user_state)
    }

    pub async fn send_create_to_transfer(&self, pub_key: &str) -> EyreResult<String> {
        let user_state = self.get_user_state(self.from_state_id).await?;

        let body = json!({
                "jsonrpc": "2.0",
                "method": "hubble_sendTransaction",
                "params": [
                {
                    "Type": "CREATE2TRANSFER",
                    "ToPublicKey": pub_key,
                    "Amount": self.airdrop_amount.to_string(),
                    "Fee": "1",
                    "Nonce": user_state.nonce,
                    "FromStateID": self.from_state_id,
                    "Signature": "0xABCD0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
                ],
                "id": 1
            }
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri(self.commander_uri.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string().into())
            ?;

        let res = self.client.request(req).await?;

        // asynchronously aggregate the chunks of the body
        let body = hyper::body::aggregate(res).await?;

        // try to parse as json with serde_json
        let tx_result: Value = serde_json::from_reader(body.reader())?;

        let tx_hash = if let Some(tx_hash) = tx_result.get("result") {
            Ok(tx_hash)
        } else if let Some(error) = tx_result.get("error") {
            println!("Error {:?}", error);
            // TODO report error
            Err(Error::HubbleError)
        } else {
            Err(Error::HubbleError)
        }?;

        Ok(tx_hash.to_string())
    }

    pub async fn get_transfer_data(&self, tx_hash: &str) -> EyreResult<CommitmentDetails> {
        let (batch_id, commitment_idx) = self.get_transfer_by_hash(tx_hash).await?;
        let transfer_idx = self.get_transfer_idx(tx_hash, batch_id, commitment_idx).await?;
        println!("Transfer idx {}", transfer_idx);

        return Ok(CommitmentDetails{
            batch_id: U256::from(batch_id),
            commitment_idx: U256::from(commitment_idx),
            transfer_idx: U256::from(transfer_idx),
        })
    }

    pub async fn get_transfer_by_hash(&self, tx_hash: &str) -> EyreResult<(u64, u64)> {
        let body: Value = json!({
            "jsonrpc":  "2.0",
            "method": "hubble_getTransaction",
            "params": [
                tx_hash.replace("\"", "")
            ],
            "id": 1u32,
        });
        println!("Body {}", body.to_string());

        let req = Request::builder()
            .method(Method::POST)
            .uri(self.commander_uri.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string().into())
            ?;

        let res = self.client.request(req).await?;
        println!("Res {:?}", res);

        // asynchronously aggregate the chunks of the body
        let body = hyper::body::aggregate(res).await?;

        // try to parse as json with serde_json
        let tx_result: Value = serde_json::from_reader(body.reader())?;
        println!("Tx result {}", tx_result);

        let res = tx_result.get("result").ok_or(Error::HubbleError)?;
        let status = res.get("Status").ok_or(Error::HubbleError)?;
        if status == "PENDING" {
            bail!("Pending tx")
        }
        let tx = res.get("Transaction").ok_or(Error::HubbleError)?;
        let commitment_id = tx.get("CommitmentID").ok_or(Error::HubbleError)?;
        let (batch_id, commitment_idx) = (commitment_id.get("BatchID").ok_or(Error::HubbleError)?, commitment_id.get("IndexInBatch").ok_or(Error::HubbleError)?);
        let batch_id = batch_id.to_string().replace("\"", "").parse::<u64>()?;
        let commitment_idx = commitment_idx.as_u64().ok_or(Error::HubbleError)?;
        Ok((batch_id, commitment_idx))
    }

    pub async fn get_transfer_idx(&self, tx_hash: &str, batch_id: u64, commitment_idx: u64) -> EyreResult<u64> {
        let body: Value = json!({
            "jsonrpc":  "2.0",
            "method": "hubble_getCommitment",
            "params": [{
                "BatchID": batch_id.to_string(),
                "IndexInBatch": commitment_idx,
            }],
            "id": 1u32,
        });

        println!("Body {}", body.to_string());

        let req = Request::builder()
            .method(Method::POST)
            .uri(self.commander_uri.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string().into())
            ?;

        let res = self.client.request(req).await?;
        println!("Res {:?}", res);

        // asynchronously aggregate the chunks of the body
        let body = hyper::body::aggregate(res).await?;

        // try to parse as json with serde_json
        let tx_result: Value = serde_json::from_reader(body.reader())?;

        let res = tx_result.get("result").ok_or(Error::HubbleError)?;
        let status = res.get("Status").ok_or(Error::HubbleError)?;
        let txs = res.get("Transactions").ok_or(Error::HubbleError)?;
        let tx_array = txs.as_array().ok_or(Error::HubbleError)?;
        for (i, tx) in tx_array.as_slice().iter().enumerate() {
            let hash = tx.get("Hash").ok_or(Error::HubbleError)?;
            println!("Comparing hash {} {}", i, hash);
            if hash == tx_hash {
                println!("Found {}", hash);
                return Ok(i.try_into()?)
            }
        }
        bail!("TX not found")
    }
}
