use bytes::Bytes;
use hyper::HeaderMap;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub duration_ms: u64,
}

impl HttpResponse {
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

#[derive(Debug, Clone)]
pub struct SendHistoryEntry {
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub body_len: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RepeaterTab {
    pub id: usize,
    pub name: String,
    pub request_text: String,
    pub response: Option<HttpResponse>,
    pub is_sending: bool,
    pub error: Option<String>,
    pub history: Vec<SendHistoryEntry>,
}

impl RepeaterTab {
    pub fn new(id: usize, name: impl Into<String>, request_text: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            request_text: request_text.into(),
            response: None,
            is_sending: false,
            error: None,
            history: Vec::new(),
        }
    }
}
