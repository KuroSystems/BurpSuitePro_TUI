use bytes::Bytes;
use chrono::{DateTime, Local};
use hyper::{HeaderMap, Uri};

#[derive(Debug, Clone)]
pub struct HttpFlow {
    pub id: u64,
    pub timestamp: DateTime<Local>,
    pub method: String,
    pub uri: String,
    pub status: Option<u16>,
    pub request_headers: HeaderMap,
    pub request_body: Bytes,
    pub response_headers: Option<HeaderMap>,
    pub response_body: Option<Bytes>,
    pub duration_ms: Option<u64>,
}

impl HttpFlow {
    pub fn host(&self) -> String {
        self.uri
            .parse::<Uri>()
            .ok()
            .and_then(|uri| uri.host().map(ToOwned::to_owned))
            .or_else(|| {
                self.request_headers
                    .get(hyper::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn path(&self) -> String {
        self.uri
            .parse::<Uri>()
            .ok()
            .and_then(|uri| uri.path_and_query().map(|path| path.as_str().to_string()))
            .unwrap_or_else(|| self.uri.clone())
    }

    pub fn response_len(&self) -> usize {
        self.response_body.as_ref().map(Bytes::len).unwrap_or_default()
    }

    pub fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let query = query.to_ascii_lowercase();
        self.method.to_ascii_lowercase().contains(&query)
            || self.uri.to_ascii_lowercase().contains(&query)
            || self
                .status
                .map(|status| status.to_string().contains(&query))
                .unwrap_or(false)
    }
}
