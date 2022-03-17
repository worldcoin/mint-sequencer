use crate::{
    app::App,
    ethereum::{BLSPubKey, CommitmentProof},
};
use ::prometheus::{opts, register_counter, register_histogram, Counter, Histogram};
use ethers::prelude::{Bytes, H256, U256};
use eyre::{bail, ensure, Error as EyreError, Result as EyreResult, WrapErr as _};
use futures::Future;
use hyper::{
    body::Buf,
    header,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::Arc,
};
use structopt::StructOpt;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{error, info, trace};
use url::{Host, Url};
use semaphore::hash::Hash;

#[derive(Clone, Debug, PartialEq, StructOpt)]
pub struct Options {
    /// API Server url
    #[structopt(long, env = "SERVER", default_value = "http://127.0.0.1:8081/")]
    pub server: Url,
}

static REQUESTS: Lazy<Counter> =
    Lazy::new(|| register_counter!(opts!("api_requests", "Number of requests received.")).unwrap());
static STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "api_response_status",
        "The API responses by status code.",
        &["status_code"]
    )
    .unwrap()
});
static LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("api_latency_seconds", "The API latency in seconds.").unwrap()
});
#[allow(dead_code)]
const CONTENT_JSON: &str = "application/json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateToTransferRequest {
    pub_key: BLSPubKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitProofRequest {
    group_id:        usize,
    pub_key:         BLSPubKey,
    proof:           CommitmentProof,
    nullifiers_hash: U256,
    tx_hash:         H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalRequest {
    group_id:           usize,
    external_nullifier: U256,
    signal:             U256,
    nullifier_hash:     Hash,
    proof:              CommitmentProof,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid method")]
    InvalidMethod,
    #[error("invalid content type")]
    InvalidContentType,
    #[error("invalid serialization format")]
    InvalidSerialization(#[from] serde_json::Error),
    #[error("HubbleError: `{0}`")]
    HubbleError(String),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Other(#[from] EyreError),
}

#[must_use]
pub fn create_hubble_field_not_found_error(field: &str, value: &Value) -> String {
    format!("Field: {} not found in serde value: {}", field, value)
}

impl Error {
    fn to_response(&self) -> hyper::Response<Body> {
        hyper::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(hyper::Body::from(self.to_string()))
            .expect("Failed to convert error string into hyper::Body")
    }
}

/// Parse a [`Request<Body>`] as JSON using Serde and handle using the provided
/// method.
#[allow(dead_code)]
async fn json_middleware<F, T, S, U>(
    request: Request<Body>,
    mut next: F,
) -> Result<Response<Body>, Error>
where
    T: DeserializeOwned + Send,
    F: FnMut(T) -> S + Send,
    S: Future<Output = Result<U, Error>> + Send,
    U: Serialize,
{
    let valid_content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .map_or(false, |content_type| content_type == CONTENT_JSON);
    if !valid_content_type {
        return Err(Error::InvalidContentType);
    }
    let body = hyper::body::aggregate(request).await?;
    let request = serde_json::from_reader(body.reader())?;
    let response = next(request).await?;
    let json = serde_json::to_string_pretty(&response)?;
    Ok(Response::new(Body::from(json)))
}

#[allow(clippy::unused_async)]
async fn route(request: Request<Body>, app: Arc<App>) -> Result<Response<Body>, hyper::Error> {
    // Measure and log request
    let _timer = LATENCY.start_timer(); // Observes on drop
    REQUESTS.inc();
    trace!(url = %request.uri(), "Receiving request");

    // Route requests
    #[allow(clippy::match_single_binding)]
    let result = match (request.method(), request.uri().path()) {
        (&Method::POST, "/sendCreateToTransfer") => {
            json_middleware(request, |request: CreateToTransferRequest| {
                let app = app.clone();
                async move { app.send_create_to_transfer(&request.pub_key).await }
            })
            .await
        }
        (&Method::POST, "/submitProof") => {
            json_middleware(request, |request: SubmitProofRequest| {
                let app = app.clone();
                async move {
                    app.submit_proof(
                        request.group_id,
                        &request.pub_key,
                        request.proof,
                        request.nullifiers_hash,
                        &request.tx_hash,
                    )
                    .await
                }
            })
            .await
        }
        (&Method::POST, "/signal") => {
            json_middleware(request, |request: SignalRequest| {
                let app = app.clone();
                async move {
                    app.signal(
                        request.group_id,
                        request.external_nullifier,
                        request.signal,
                        request.nullifier_hash,
                        request.proof,
                    )
                    .await
                }
            })
            .await
        }
        _ => Err(Error::InvalidMethod),
    };
    let response = result.unwrap_or_else(|err| err.to_response());

    // Measure result and return
    STATUS
        .with_label_values(&[response.status().as_str()])
        .inc();
    Ok(response)
}

/// # Errors
///
/// Will return `Err` if `options.server` URI is not http, incorrectly includes
/// a path beyond `/`, or cannot be cast into an IP address. Also returns an
/// `Err` if the server cannot bind to the given address.
pub async fn main(
    app: Arc<App>,
    options: Options,
    shutdown: broadcast::Sender<()>,
) -> EyreResult<()> {
    ensure!(
        options.server.scheme() == "http",
        "Only http:// is supported in {}",
        options.server
    );
    ensure!(
        options.server.path() == "/",
        "Only / is supported in {}",
        options.server
    );
    let ip: IpAddr = match options.server.host() {
        Some(Host::Ipv4(ip)) => ip.into(),
        Some(Host::Ipv6(ip)) => ip.into(),
        Some(_) => bail!("Cannot bind {}", options.server),
        None => Ipv4Addr::LOCALHOST.into(),
    };
    let port = options.server.port().unwrap_or(9998);
    let addr = SocketAddr::new(ip, port);

    let listener = TcpListener::bind(&addr)?;

    // app.signal(0, U256::one(), U256::one(), Hash::from(U256::one()), [U256::one(); 8]).await?;
    bind_from_listener(app.clone(), listener, shutdown).await?;

    Ok(())
}

/// # Errors
///
/// Will return `Err` if the provided `listener` address cannot be accessed or
/// if the server fails to bind to the given address.
pub async fn bind_from_listener(
    app: Arc<App>,
    listener: TcpListener,
    shutdown: broadcast::Sender<()>,
) -> EyreResult<()> {
    let local_addr = listener.local_addr()?;
    let make_svc = make_service_fn(move |_| {
        // Clone here as `make_service_fn` is called for every connection
        let app = app.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                // Clone here as `service_fn` is called for every request
                let app = app.clone();
                route(req, app)
            }))
        }
    });

    let server = Server::from_tcp(listener)
        .wrap_err("Failed to bind address")?
        .serve(make_svc)
        .with_graceful_shutdown(async move {
            shutdown.subscribe().recv().await.ok();
        });

    info!(url = %local_addr, "Server listening");

    server.await?;
    Ok(())
}

#[cfg(feature = "bench")]
#[allow(clippy::wildcard_imports, unused_imports)]
pub mod bench {
    use super::*;
    use crate::bench::runtime;
    use criterion::Criterion;

    pub fn group(_c: &mut Criterion) {
        //     bench_hello_world(c);
    }

    // fn bench_hello_world(c: &mut Criterion) {
    // }
}
