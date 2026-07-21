use std::{convert::Infallible, sync::Arc, time::Instant};

use bytes::Bytes;
use chrono::Local;
use color_eyre::eyre::{eyre, Context, Result};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::HOST,
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use rustls::ServerConfig;
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::{
    models::{
        flow::HttpFlow,
        websocket::{WebSocketDirection, WebSocketFrameRecord},
    },
    store::FlowStore,
};

use super::{
    ca::ensure_ca_certificate,
    handler::{dropped_response, Decision},
    CaAuthority, InterceptHandler, ProxyConfig, ProxyRequest, ProxyResponse,
};

type ProxyBody = BoxBody<Bytes, Infallible>;
type SharedHandler<H> = Arc<Mutex<H>>;

pub fn run_proxy<H>(config: ProxyConfig, handler: H, flow_store: FlowStore) -> JoinHandle<Result<()>>
where
    H: InterceptHandler,
{
    tokio::spawn(async move { serve_proxy(config, handler, flow_store).await })
}

async fn serve_proxy<H>(config: ProxyConfig, handler: H, flow_store: FlowStore) -> Result<()>
where
    H: InterceptHandler,
{
    let ca = Arc::new(ensure_ca_certificate(&config)?);
    let handler = Arc::new(Mutex::new(handler));
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .wrap_err("failed to create outbound HTTP client")?;
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind proxy listener at {}", config.listen_addr))?;

    info!(listen_addr = %config.listen_addr, "proxy listening");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .wrap_err("failed to accept proxy connection")?;
        let ca = Arc::clone(&ca);
        let handler = Arc::clone(&handler);
        let client = client.clone();
        let flow_store = flow_store.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |request| {
                route_proxy_request(
                    request,
                    client.clone(),
                    Arc::clone(&ca),
                    Arc::clone(&handler),
                    flow_store.clone(),
                )
            });

            if let Err(error) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                debug!(%peer_addr, ?error, "proxy connection ended");
            }
        });
    }
}

async fn route_proxy_request<H>(
    request: Request<Incoming>,
    client: Client,
    ca: Arc<CaAuthority>,
    handler: SharedHandler<H>,
    flow_store: FlowStore,
) -> Result<Response<ProxyBody>, Infallible>
where
    H: InterceptHandler,
{
    let response = if request.method() == Method::CONNECT {
        handle_connect(request, client, ca, handler, flow_store).await
    } else {
        handle_plain_http(request, client, handler, None, flow_store).await
    };

    Ok(response.unwrap_or_else(error_response))
}

async fn handle_connect<H>(
    request: Request<Incoming>,
    client: Client,
    ca: Arc<CaAuthority>,
    handler: SharedHandler<H>,
    flow_store: FlowStore,
) -> Result<Response<ProxyBody>>
where
    H: InterceptHandler,
{
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| request.uri().path().split('/').next().map(ToOwned::to_owned))
        .ok_or_else(|| eyre!("CONNECT request missing authority"))?;
    let domain = authority
        .split(':')
        .next()
        .filter(|domain| !domain.is_empty())
        .ok_or_else(|| eyre!("CONNECT authority has empty host"))?
        .to_string();

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => {
                if let Err(error) = mitm_tls_connection(upgraded, domain, authority, client, ca, handler, flow_store).await {
                    warn!(?error, "MITM tunnel failed");
                }
            }
            Err(error) => warn!(?error, "CONNECT upgrade failed"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("static CONNECT response is valid"))
}

async fn mitm_tls_connection<H>(
    upgraded: hyper::upgrade::Upgraded,
    domain: String,
    authority: String,
    client: Client,
    ca: Arc<CaAuthority>,
    handler: SharedHandler<H>,
    flow_store: FlowStore,
) -> Result<()>
where
    H: InterceptHandler,
{
    let issued = ca.issue_domain_certificate(&domain)?;
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(issued.cert_chain, issued.private_key)
        .wrap_err("failed to build per-domain TLS config")?;
    // Only advertise HTTP/1.1 to the browser for now. Advertising h2 makes
    // modern browsers negotiate HTTP/2, but this MITM listener currently serves
    // the decrypted client side with Hyper's HTTP/1.1 server. That protocol
    // mismatch causes TLS tunnels to reset after the CA is trusted.
    // The upstream leg can still negotiate HTTP/2 through reqwest independently.
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .wrap_err("failed to complete client TLS handshake")?;

    let service = service_fn(move |request| {
        handle_plain_http(
            request,
            client.clone(),
            Arc::clone(&handler),
            Some(authority.clone()),
            flow_store.clone(),
        )
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .await
        .wrap_err("failed to serve HTTPS MITM HTTP/1.1 connection")?;

    Ok(())
}

async fn handle_plain_http<H>(
    request: Request<Incoming>,
    client: Client,
    handler: SharedHandler<H>,
    tls_authority: Option<String>,
    flow_store: FlowStore,
) -> Result<Response<ProxyBody>>
where
    H: InterceptHandler,
{
    let started_at = Instant::now();
    let timestamp = Local::now();
    let id = flow_store.next_id();
    let mut request = collect_proxy_request(request, tls_authority).await?;
    if is_websocket_upgrade(&request) {
        record_websocket_handshake(&flow_store, id, request.uri().to_string(), request.body());
    }

    let decision = {
        let mut handler = handler.lock().await;
        handler.on_request(&mut request)
    };

    if decision == Decision::Drop {
        let mut response = dropped_response();
        {
            let mut handler = handler.lock().await;
            handler.on_response(&mut response);
        }
        record_flow(&flow_store, id, timestamp, started_at, &request, &response);
        return Ok(proxy_response_to_hyper(response));
    }

    let mut response = forward_request(&client, request.clone()).await?;
    {
        let mut handler = handler.lock().await;
        handler.on_response(&mut response);
    }
    record_flow(&flow_store, id, timestamp, started_at, &request, &response);

    Ok(proxy_response_to_hyper(response))
}

fn record_flow(
    flow_store: &FlowStore,
    id: u64,
    timestamp: chrono::DateTime<Local>,
    started_at: Instant,
    request: &ProxyRequest,
    response: &ProxyResponse,
) {
    flow_store.push_flow(HttpFlow {
        id,
        timestamp,
        method: request.method().to_string(),
        uri: request.uri().to_string(),
        status: Some(response.status().as_u16()),
        request_headers: request.headers().clone(),
        request_body: request.body().clone(),
        response_headers: Some(response.headers().clone()),
        response_body: Some(response.body().clone()),
        duration_ms: Some(started_at.elapsed().as_millis() as u64),
    });
}

async fn collect_proxy_request(
    request: Request<Incoming>,
    tls_authority: Option<String>,
) -> Result<ProxyRequest> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .wrap_err("failed to read request body")?
        .to_bytes();
    let uri = normalize_uri(&parts.uri, tls_authority.as_deref())?;

    let mut builder = Request::builder().method(parts.method).uri(uri).version(parts.version);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop_header(name) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    Ok(builder
        .body(body)
        .wrap_err("failed to build collected proxy request")?)
}

fn normalize_uri(uri: &Uri, tls_authority: Option<&str>) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }

    let authority = tls_authority.ok_or_else(|| eyre!("origin-form HTTP request missing authority"))?;
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    format!("https://{authority}{path}")
        .parse::<Uri>()
        .wrap_err("failed to normalize HTTPS MITM URI")
}

async fn forward_request(client: &Client, request: ProxyRequest) -> Result<ProxyResponse> {
    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .wrap_err("failed to convert request method")?;
    let mut builder = client.request(method, request.uri().to_string());

    for (name, value) in request.headers().iter() {
        if is_hop_by_hop_header(name) || name.as_str().eq_ignore_ascii_case(HOST.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    let response = builder
        .body(request.body().clone())
        .send()
        .await
        .wrap_err("failed to forward proxy request")?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .wrap_err("failed to read upstream response body")?;

    let mut response_builder = Response::builder().status(status.as_u16());
    for (name, value) in headers.iter() {
        if is_hop_by_hop_header(name) {
            continue;
        }
        response_builder = response_builder.header(name.clone(), value.clone());
    }

    Ok(response_builder
        .body(body)
        .wrap_err("failed to build proxy response")?)
}

fn proxy_response_to_hyper(response: ProxyResponse) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(parts.version);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name.clone(), value.clone());
    }
    builder
        .body(full_body(body))
        .expect("proxy response parts are valid")
}

fn is_websocket_upgrade(request: &ProxyRequest) -> bool {
    request
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        || request
            .headers()
            .get(hyper::header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

fn record_websocket_handshake(flow_store: &FlowStore, flow_id: u64, url: String, body: &Bytes) {
    flow_store.push_websocket_frame(WebSocketFrameRecord {
        id: 0,
        timestamp: Local::now(),
        flow_id: Some(flow_id),
        url,
        direction: WebSocketDirection::ClientToServer,
        opcode: "handshake".to_string(),
        length: body.len(),
        payload_preview: "HTTP Upgrade: websocket".to_string(),
    });
}

fn is_hop_by_hop_header(name: &hyper::header::HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
    )
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).boxed()
}

fn empty_body() -> ProxyBody {
    full_body(Bytes::new())
}

fn error_response(error: color_eyre::Report) -> Response<ProxyBody> {
    error!(?error, "proxy request failed");
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(full_body(Bytes::from(format!("proxy error: {error:#}"))))
        .expect("static error response is valid")
}
