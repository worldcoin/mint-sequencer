use std::str::FromStr;

use ethers::prelude::{H256, U256};
use eyre::{bail, Result as EyreResult};
use reqwest::{header::CONTENT_TYPE, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use structopt::StructOpt;

use crate::{
    ethereum::BLSPubKey,
    server::{create_hubble_field_not_found_error, Error},
};

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    #[structopt(long, env, default_value = "http://localhost:8080")]
    commander_url: Url,

    #[structopt(long, env, default_value = "50")]
    airdrop_amount: u32,

    #[structopt(long, env, default_value = "2")]
    from_state_id: u32,
}

pub struct Hubble {
    client:         Client,
    commander_url:  Url,
    airdrop_amount: u32,
    from_state_id:  u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentDetails {
    pub batch_id:       U256,
    pub commitment_idx: U256,
    pub transfer_idx:   U256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserState {
    #[serde(rename = "StateID")]
    state_id:   u32,
    #[serde(rename = "PubKeyID")]
    pub_key_id: u32,
    #[serde(rename = "TokenID")]
    token_id:   String,
    #[serde(rename = "Balance")]
    balance:    U256,
    #[serde(rename = "Nonce")]
    nonce:      String,
}

impl Hubble {
    pub async fn new(options: Options) -> EyreResult<Self> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            commander_url: options.commander_url,
            airdrop_amount: options.airdrop_amount,
            from_state_id: options.from_state_id,
        })
    }

    /// # Errors
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

        let response = self
            .client
            .post(self.commander_url.clone())
            .body(body.to_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;
        let json_body: Value = response.json().await?;

        let user_state = json_body.get("result").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("result", &json_body))
        })?;
        let user_state = from_str::<UserState>(&user_state.to_string())?;
        Ok(user_state)
    }

    /// # Errors
    pub async fn send_create_to_transfer(&self, pub_key: &BLSPubKey) -> EyreResult<String> {
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

        let response = self
            .client
            .post(self.commander_url.clone())
            .body(body.to_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;
        let json_body: Value = response.json().await?;

        let tx_hash = json_body.get("result").map_or_else(
            || {
                json_body.get("error").map_or_else(
                    || {
                        Err(Error::HubbleError(create_hubble_field_not_found_error(
                            "error", &json_body,
                        )))
                    },
                    |error| Err(Error::HubbleError(error.to_string())),
                )
            },
            Ok,
        )?;

        Ok(tx_hash.to_string())
    }

    /// # Errors
    pub async fn get_transfer_data(&self, tx_hash: &H256) -> EyreResult<CommitmentDetails> {
        let (batch_id, commitment_idx) = self.get_transfer_by_hash(tx_hash).await?;
        let transfer_idx = self
            .get_transfer_idx(tx_hash, batch_id, commitment_idx)
            .await?;

        Ok(CommitmentDetails {
            batch_id:       U256::from(batch_id),
            commitment_idx: U256::from(commitment_idx),
            transfer_idx:   U256::from(transfer_idx),
        })
    }

    /// # Errors
    pub async fn get_transfer_by_hash(&self, tx_hash: &H256) -> EyreResult<(u64, u64)> {
        let body: Value = json!({
            "jsonrpc":  "2.0",
            "method": "hubble_getTransaction",
            "params": [
                tx_hash
            ],
            "id": 1u32,
        });

        let response = self
            .client
            .post(self.commander_url.clone())
            .body(body.to_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;
        let json_body: Value = response.json().await?;

        let response = json_body.get("result").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("result", &json_body))
        })?;
        let status = response.get("Status").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("Status", response))
        })?;
        if status == "PENDING" {
            bail!("Pending tx")
        }
        let tx = response.get("Transaction").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("Transaction", response))
        })?;
        let commitment_id = tx.get("CommitmentID").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("CommitmentID", tx))
        })?;
        let (batch_id, commitment_idx) = (
            commitment_id.get("BatchID").ok_or_else(|| {
                Error::HubbleError(create_hubble_field_not_found_error(
                    "BatchID",
                    commitment_id,
                ))
            })?,
            commitment_id.get("IndexInBatch").ok_or_else(|| {
                Error::HubbleError(create_hubble_field_not_found_error(
                    "IndexInBatch",
                    commitment_id,
                ))
            })?,
        );
        let batch_id = batch_id.to_string().replace('\"', "").parse::<u64>()?;
        let commitment_idx = commitment_idx.as_u64().ok_or_else(|| {
            Error::HubbleError(format!(
                "Cannot parse `commitment_idx`: {} as u64",
                commitment_idx
            ))
        })?;
        Ok((batch_id, commitment_idx))
    }

    /// # Errors
    pub async fn get_transfer_idx(
        &self,
        tx_hash: &H256,
        batch_id: u64,
        commitment_idx: u64,
    ) -> EyreResult<u64> {
        let body: Value = json!({
            "jsonrpc":  "2.0",
            "method": "hubble_getCommitment",
            "params": [{
                "BatchID": batch_id.to_string(),
                "IndexInBatch": commitment_idx,
            }],
            "id": 1u32,
        });

        let response = self
            .client
            .post(self.commander_url.clone())
            .body(body.to_string())
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;
        let json_body: Value = response.json().await?;

        let response = json_body.get("result").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("result", &json_body))
        })?;
        let status = response.get("Status").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error("Status", response))
        })?;
        if status == "PENDING" {
            bail!("Tx pending")
        }
        let txs = response.get("Transactions").ok_or_else(|| {
            Error::HubbleError(create_hubble_field_not_found_error(
                "Transactions",
                response,
            ))
        })?;
        let tx_array = txs
            .as_array()
            .ok_or_else(|| Error::HubbleError(format!("Cannot parse `txs`: {} as array", txs)))?;
        for (i, tx) in tx_array.as_slice().iter().enumerate() {
            let hash = tx.get("Hash").ok_or_else(|| {
                Error::HubbleError(create_hubble_field_not_found_error("Hash", tx))
            })?;
            let hash = H256::from_str(&hash.to_string().replace('\"', ""))?;
            if hash == *tx_hash {
                return Ok(i.try_into()?);
            }
        }
        bail!("TX not found")
    }
}
