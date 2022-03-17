mod contract;

use self::contract::{Semaphore, WalletClaims};
use crate::{hash::Hash, hubble::CommitmentDetails};
use ethers::{
    core::k256::ecdsa::SigningKey,
    middleware::{NonceManagerMiddleware, SignerMiddleware},
    prelude::{Bytes, U256},
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::Address,
    utils::keccak256,
};
use eyre::{bail, eyre, Result as EyreResult};
use fixed_hash::construct_fixed_hash;
use impl_serde::impl_fixed_hash_serde;
use std::sync::Arc;
use structopt::StructOpt;
use tracing::info;
use url::Url;

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    /// Ethereum API Provider
    #[structopt(long, env, default_value = "http://localhost:8545")]
    pub ethereum_provider: Url,

    /// Semaphore contract address.
    #[structopt(long, env, default_value = "07389715AE1f0a891fbA82e65099F6a3FA7dA593")]
    pub semaphore_address: Address,

    /// WalletClaims contract address.
    #[structopt(long, env, default_value = "E97bF95177738733e5CE1f9ae1933a73b6f158D4")]
    pub wallet_claims_address: Address,

    /// Private key used for transaction signing
    #[structopt(
        long,
        env,
        default_value = "ee79b5f6e221356af78cf4c36f4f7885a11b67dfcc81c34d80249947330c0f82"
    )]
    // NOTE: We abuse `Hash` here because it has the right `FromStr` implementation.
    pub signing_key: Hash,

    #[structopt(long, env, default_value = "123", parse(try_from_str = U256::from_dec_str))]
    pub external_nullifier: U256,

    /// If this module is being run within an integration test
    /// Short and long flags (-t, --test)
    #[structopt(long, parse(try_from_str), env, default_value = "true")]
    pub eip1559: bool,
}

// Code out the provider stack in types
// Needed because of <https://github.com/gakonst/ethers-rs/issues/592>
type Provider0 = Provider<Http>;
type Provider1 = SignerMiddleware<Provider0, Wallet<SigningKey>>;
type Provider2 = NonceManagerMiddleware<Provider1>;
type ProviderStack = Provider2;

pub type CommitmentProof = [U256; 8];

construct_fixed_hash! {
    pub struct BLSPubKey(128);
}

impl_fixed_hash_serde!(BLSPubKey, 128);

#[allow(dead_code)]
pub struct Ethereum {
    provider: Arc<ProviderStack>,
    semaphore: Semaphore<ProviderStack>,
    wallet_claims: WalletClaims<ProviderStack>,
    external_nullifier: U256,
    eip1559: bool,
}

impl Ethereum {
    pub async fn new(options: Options) -> EyreResult<Self> {
        // Connect to the Ethereum provider
        // TODO: Support WebSocket and IPC.
        // Blocked on <https://github.com/gakonst/ethers-rs/issues/592>
        let (provider, chain_id) = {
            info!(
                provider = %&options.ethereum_provider,
                "Connecting to Ethereum"
            );
            let http = Http::new(options.ethereum_provider);
            let provider = Provider::new(http);
            let chain_id = provider.get_chainid().await?;
            let latest_block = provider.get_block_number().await?;
            info!(%chain_id, %latest_block, "Connected to Ethereum");
            (provider, chain_id)
        };

        // TODO: Add metrics layer that measures the time each rpc call takes.
        // TODO: Add logging layer that logs calls to major RPC endpoints like
        // send_transaction.

        // Construct a local key signer
        let (provider, address) = {
            let signing_key = SigningKey::from_bytes(options.signing_key.as_bytes_be())?;
            let signer = LocalWallet::from(signing_key);
            let address = signer.address();
            let chain_id: u64 = chain_id.try_into().map_err(|e| eyre!("{}", e))?;
            let signer = signer.with_chain_id(chain_id);
            let provider = SignerMiddleware::new(provider, signer);
            info!(?address, "Constructed wallet");
            (provider, address)
        };

        // TODO: Integrate gas price oracle to not rely on node's `eth_gasPrice`

        // Manage nonces locally
        let provider = { NonceManagerMiddleware::new(provider, address) };

        // Add a 10 block delay to avoid having to handle re-orgs
        // TODO: Pending <https://github.com/gakonst/ethers-rs/pull/568/files>
        // let provider = {
        //     const BLOCK_DELAY: u8 = 10;
        //     TimeLag::<BLOCK_DELAY>::new(provider)
        // };

        // Connect to Contract
        let provider = Arc::new(provider);
        let semaphore = Semaphore::new(options.semaphore_address, provider.clone());
        let wallet_claims = WalletClaims::new(options.wallet_claims_address, provider.clone());
        // TODO: Test contract connection by calling a view function.

        Ok(Self {
            provider,
            semaphore,
            wallet_claims,
            external_nullifier: options.external_nullifier,
            eip1559: options.eip1559,
        })
    }

    pub async fn root(&self) -> EyreResult<U256> {
        Ok(self.semaphore.root().call().await?)
    }

    pub fn hex_to_bytes(input: &str) -> EyreResult<Bytes> {
        if input.len() >= 2 && &input[0..2] == "0x" {
            let bytes: Vec<u8> = hex::decode(&input[2..])?;
            Ok(bytes.into())
        } else {
            bail!("Expected 0x prefix")
        }
    }

    pub fn pub_key_to_signals(pub_key: &BLSPubKey) -> EyreResult<(Bytes, U256)> {
        let signal: Bytes = keccak256(pub_key.0).into();
        let signal_hash = Self::hex_to_bytes(&signal.to_string())?;
        let signal_hash: U256 = keccak256(signal_hash).into();
        let signal_hash = signal_hash >> 8;
        Ok((signal, signal_hash))
    }

    pub async fn pre_broadcast_check(
        &self,
        pub_key: &BLSPubKey,
        root: U256,
        proof: CommitmentProof,
        nullifiers_hash: U256,
    ) -> EyreResult<bool> {
        let (signal, signal_hash) = Self::pub_key_to_signals(pub_key)?;
        Ok(self
            .semaphore
            .pre_broadcast_check(
                signal,
                proof,
                root,
                nullifiers_hash,
                signal_hash,
                self.external_nullifier,
            )
            .call()
            .await?)
    }

    pub async fn commit(
        &self,
        pub_key: &BLSPubKey,
        root: U256,
        proof: CommitmentProof,
        nullifiers_hash: U256,
        commitment_details: CommitmentDetails,
    ) -> EyreResult<()> {
        info!(%pub_key, %root, %nullifiers_hash, "Committing to airdrop");
        let (signal, _signal_hash) = Self::pub_key_to_signals(pub_key)?;
        let tx = self.wallet_claims.commit(
            proof,
            signal,
            commitment_details.batch_id,
            commitment_details.commitment_idx,
            commitment_details.transfer_idx,
            root,
            nullifiers_hash,
        );

        let pending_tx = if self.eip1559 {
            self.provider.send_transaction(tx.tx, None).await?
        } else {
            // Our tests use ganache which doesn't support EIP-1559 transactions yet.
            self.provider.send_transaction(tx.legacy().tx, None).await?
        };

        let receipt = pending_tx.await.map_err(|e| eyre!(e))?;
        if receipt.is_none() {
            // This should only happen if the tx is no longer in the mempool, meaning the tx
            // was dropped.
            return Err(eyre!("tx dropped from mempool"));
        }

        Ok(())
    }
}
