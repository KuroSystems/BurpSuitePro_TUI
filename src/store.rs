use std::{
    sync::{atomic::{AtomicU64, Ordering}, Arc, RwLock},
};

use tokio::sync::mpsc;
use tracing::warn;

use crate::{events::ProxyEvent, models::{flow::HttpFlow, websocket::WebSocketFrameRecord}};

#[derive(Debug, Clone)]
pub struct FlowStore {
    flows: Arc<RwLock<Vec<HttpFlow>>>,
    websocket_frames: Arc<RwLock<Vec<WebSocketFrameRecord>>>,
    tx: mpsc::Sender<ProxyEvent>,
    next_id: Arc<AtomicU64>,
    next_ws_id: Arc<AtomicU64>,
}

impl FlowStore {
    pub fn new() -> (Self, mpsc::Receiver<ProxyEvent>) {
        let (tx, rx) = mpsc::channel(1024);
        (
            Self {
                flows: Arc::new(RwLock::new(Vec::new())),
                websocket_frames: Arc::new(RwLock::new(Vec::new())),
                tx,
                next_id: Arc::new(AtomicU64::new(1)),
                next_ws_id: Arc::new(AtomicU64::new(1)),
            },
            rx,
        )
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_websocket_id(&self) -> u64 {
        self.next_ws_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn push_flow(&self, flow: HttpFlow) {
        let id = flow.id;
        match self.flows.write() {
            Ok(mut flows) => flows.push(flow),
            Err(error) => {
                warn!(?error, "flow store write lock poisoned");
                return;
            }
        }

        let _ = self.tx.try_send(ProxyEvent::NewFlow(id));
    }

    pub fn set_flows(&self, loaded_flows: Vec<HttpFlow>) {
        let next_id = loaded_flows.iter().map(|flow| flow.id).max().unwrap_or(0) + 1;
        self.next_id.store(next_id, Ordering::Relaxed);
        if let Ok(mut flows) = self.flows.write() {
            *flows = loaded_flows;
        }
    }

    pub fn get_by_id(&self, id: u64) -> Option<HttpFlow> {
        self.flows
            .read()
            .ok()
            .and_then(|flows| flows.iter().find(|flow| flow.id == id).cloned())
    }

    pub fn push_websocket_frame(&self, mut frame: WebSocketFrameRecord) {
        if frame.id == 0 {
            frame.id = self.next_websocket_id();
        }
        let id = frame.id;
        match self.websocket_frames.write() {
            Ok(mut frames) => frames.push(frame),
            Err(error) => {
                warn!(?error, "websocket frame store write lock poisoned");
                return;
            }
        }
        let _ = self.tx.try_send(ProxyEvent::NewWebSocketFrame(id));
    }

    pub fn websocket_snapshot(&self) -> Vec<WebSocketFrameRecord> {
        self.websocket_frames
            .read()
            .map(|frames| frames.clone())
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> Vec<HttpFlow> {
        self.flows
            .read()
            .map(|flows| flows.clone())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.flows.read().map(|flows| flows.len()).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
