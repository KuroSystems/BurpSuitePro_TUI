use bytes::Bytes;
use hyper::{Request, Response, StatusCode};
use tracing::info;

pub type ProxyRequest = Request<Bytes>;
pub type ProxyResponse = Response<Bytes>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Continue,
    Drop,
}

pub trait InterceptHandler: Send + Sync + 'static {
    fn on_request(&mut self, request: &mut ProxyRequest) -> Decision;
    fn on_response(&mut self, response: &mut ProxyResponse);
}

#[derive(Debug, Default)]
pub struct LoggingHandler;

impl InterceptHandler for LoggingHandler {
    fn on_request(&mut self, request: &mut ProxyRequest) -> Decision {
        let content_length = request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-");

        info!(
            target: "proxy::traffic",
            method = %request.method(),
            uri = %request.uri(),
            content_length,
            "proxy request"
        );

        Decision::Continue
    }

    fn on_response(&mut self, response: &mut ProxyResponse) {
        let content_length = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-");

        info!(
            target: "proxy::traffic",
            status = %response.status(),
            content_length,
            "proxy response"
        );
    }
}

pub fn dropped_response() -> ProxyResponse {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Bytes::from_static(b"request dropped by intercept handler"))
        .expect("static response is valid")
}
