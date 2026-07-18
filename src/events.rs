use crossterm::event::{KeyEvent, MouseEvent};

use crate::{
    models::{ai::AiEvent, intruder::IntruderEvent, repeater::HttpResponse},
    scanner::ActiveScannerEvent,
};

#[derive(Debug, Clone)]
pub enum ProxyEvent {
    NewFlow(u64),
    NewWebSocketFrame(u64),
}

#[derive(Debug, Clone)]
pub enum RepeaterEvent {
    SendComplete {
        tab_id: usize,
        response: Result<HttpResponse, String>,
    },
}

#[derive(Debug, Clone)]
pub enum Event {
    Tick,
    Render,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    ProxyEvent(ProxyEvent),
    RepeaterEvent(RepeaterEvent),
    IntruderEvent(IntruderEvent),
    ActiveScannerEvent(ActiveScannerEvent),
    AiEvent(AiEvent),
}
