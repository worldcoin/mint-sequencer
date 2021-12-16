use ethers::{
    abi::Address,
    core::abi::Abi,
    prelude::{
        Bytes, ContractFactory, Http, LocalWallet, NonceManagerMiddleware, Provider, Signer,
        SignerMiddleware,
    },
    utils::{Ganache, GanacheInstance},
};
use eyre::{bail, Result as EyreResult};
use hex_literal::hex;
use hyper::Client;
use mint_sequencer::{app::App, hash::Hash, server, Options};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};
use structopt::StructOpt;
use tokio::{spawn, sync::broadcast};
use url::{Host, Url};

const GANACHE_DEFAULT_WALLET_KEY: Hash = Hash(hex!(
    "1ce6a4cc4c9941a4781349f988e129accdc35a55bb3d5b1a7b342bc2171db484"
));

#[tokio::test]
async fn submit_proofs() {
    let mut options = Options::from_iter_safe(&[""]).expect("Failed to create options");
    options.server.server = Url::parse("http://127.0.0.1:0/").expect("Failed to parse URL");

    let (shutdown, _) = broadcast::channel(1);

    let (ganache, semaphore_address) = spawn_mock_chain()
        .await
        .expect("Failed to spawn ganache chain");

    options.app.ethereum.eip1559 = false;
    options.app.ethereum.ethereum_provider =
        Url::parse(&ganache.endpoint()).expect("Failed to parse ganache endpoint");
    options.app.ethereum.semaphore_address = semaphore_address;
    options.app.ethereum.signing_key = GANACHE_DEFAULT_WALLET_KEY;

    let local_addr = spawn_app(options.clone(), shutdown.clone())
        .await
        .expect("Failed to spawn app.");

    let _uri = "http://".to_owned() + &local_addr.to_string();
    let _client = Client::new();

    // TODO add relevant tests
}

async fn spawn_app(options: Options, shutdown: broadcast::Sender<()>) -> EyreResult<SocketAddr> {
    let app = Arc::new(App::new(options.app).await.expect("Failed to create App"));

    let ip: IpAddr = match options.server.server.host() {
        Some(Host::Ipv4(ip)) => ip.into(),
        Some(Host::Ipv6(ip)) => ip.into(),
        Some(_) => bail!("Cannot bind {}", options.server.server),
        None => Ipv4Addr::LOCALHOST.into(),
    };
    let port = options.server.server.port().unwrap_or(9998);
    let addr = SocketAddr::new(ip, port);
    let listener = TcpListener::bind(&addr).expect("Failed to bind random port");
    let local_addr = listener.local_addr()?;

    spawn({
        async move {
            server::bind_from_listener(app, listener, shutdown)
                .await
                .expect("Failed to bind address");
        }
    });

    Ok(local_addr)
}

#[derive(Deserialize, Serialize, Debug)]
struct CompiledContract {
    abi:      Abi,
    bytecode: String,
}

fn deserialize_to_bytes(input: String) -> EyreResult<Bytes> {
    if input.len() >= 2 && &input[0..2] == "0x" {
        let bytes: Vec<u8> = hex::decode(&input[2..])?;
        Ok(bytes.into())
    } else {
        bail!("Expected 0x prefix")
    }
}

async fn spawn_mock_chain() -> EyreResult<(GanacheInstance, Address)> {
    let ganache = Ganache::new().block_time(2u64).mnemonic("test").spawn();

    let provider = Provider::<Http>::try_from(ganache.endpoint())
        .expect("Failed to initialize ganache endpoint")
        .interval(Duration::from_millis(500u64));

    let wallet: LocalWallet = ganache.keys()[0].clone().into();

    // connect the wallet to the provider
    let client = SignerMiddleware::new(provider, wallet.clone());
    let client = NonceManagerMiddleware::new(client, wallet.address());
    let client = std::sync::Arc::new(client);

    let mimc_json = File::open("./sol/MiMC.json").expect("Failed to read MiMC.sol");
    let mimc_json: CompiledContract =
        serde_json::from_reader(mimc_json).expect("Could not parse compiled MiMC contract");
    let mimc_bytecode = deserialize_to_bytes(mimc_json.bytecode)?;

    let mimc_factory = ContractFactory::new(mimc_json.abi, mimc_bytecode, client.clone());

    let mimc_contract = mimc_factory
        .deploy(())?
        .legacy()
        .confirmations(0usize)
        .send()
        .await?;

    let semaphore_json =
        File::open("./sol/Semaphore.json").expect("Compiled contract doesn't exist");
    let semaphore_json: CompiledContract =
        serde_json::from_reader(semaphore_json).expect("Could not read contract");

    let semaphore_bytecode = semaphore_json.bytecode.replace(
        "__$cf5da3090e28b1d67a537682696360513a$__",
        &format!("{:?}", mimc_contract.address()).replace("0x", ""),
    );
    let semaphore_bytecode = deserialize_to_bytes(semaphore_bytecode)?;

    // create a factory which will be used to deploy instances of the contract
    let semaphore_factory =
        ContractFactory::new(semaphore_json.abi, semaphore_bytecode, client.clone());

    let semaphore_contract = semaphore_factory
        .deploy((4_u64, 123_u64))?
        .legacy()
        .confirmations(0usize)
        .send()
        .await?;

    Ok((ganache, semaphore_contract.address()))
}
