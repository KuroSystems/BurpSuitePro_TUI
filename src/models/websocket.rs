use chrono::{DateTime, Local};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketDirection {
    ClientToServer,
    ServerToClient,
}

impl WebSocketDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClientToServer => "client → server",
            Self::ServerToClient => "server → client",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebSocketFrameRecord {
    pub id: u64,
    pub timestamp: DateTime<Local>,
    pub flow_id: Option<u64>,
    pub url: String,
    pub direction: WebSocketDirection,
    pub opcode: String,
    pub length: usize,
    pub payload_preview: String,
}

impl WebSocketFrameRecord {
    pub fn from_tungstenite_message(
        id: u64,
        url: impl Into<String>,
        direction: WebSocketDirection,
        message: &tungstenite::Message,
    ) -> Self {
        let (opcode, payload) = match message {
            tungstenite::Message::Text(value) => ("text", value.as_bytes().to_vec()),
            tungstenite::Message::Binary(value) => ("binary", value.clone()),
            tungstenite::Message::Ping(value) => ("ping", value.clone()),
            tungstenite::Message::Pong(value) => ("pong", value.clone()),
            tungstenite::Message::Close(_) => ("close", Vec::new()),
            tungstenite::Message::Frame(frame) => ("frame", frame.payload().to_vec()),
        };
        let payload_preview = String::from_utf8_lossy(&payload)
            .chars()
            .take(160)
            .collect::<String>();
        Self {
            id,
            timestamp: Local::now(),
            flow_id: None,
            url: url.into(),
            direction,
            opcode: opcode.to_string(),
            length: payload.len(),
            payload_preview,
        }
    }
}
