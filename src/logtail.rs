use std::{collections::VecDeque, sync::{Arc, RwLock}, time::Duration};

use actix_web::{HttpRequest, HttpResponse, web};
use actix_ws::{MessageStream, Session};
use serde::{Deserialize, Serialize};
use tokio::{fs::File, sync::broadcast};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

#[derive(Clone, Serialize)]
pub struct LogLine {
    pub id: u64,
    pub data: String,
}

pub struct LogTailer {
    tx: broadcast::Sender<LogLine>,
    buffer: Arc<RwLock<RingBuffer>>,
}

struct RingBuffer {
    lines: VecDeque<LogLine>,
    max_size: usize,
    next_id: u64,
}

impl LogTailer {
    pub fn new(buffer_size: usize) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            tx,
            buffer: Arc::new(RwLock::new(RingBuffer {
                lines: VecDeque::with_capacity(buffer_size),
                max_size: buffer_size,
                next_id: 0,
            })),
        }
    }

    pub fn push(&self, data: String) {
        let mut buf = self.buffer.write().unwrap();
        let line = LogLine {
            id: buf.next_id,
            data,
        };
        buf.next_id += 1;
        if buf.lines.len() >= buf.max_size {
            buf.lines.pop_front();
        }
        buf.lines.push_back(line.clone());
        let _ = self.tx.send(line);
    }

    pub fn lines_after(&self, last_id: u64) -> Vec<LogLine> {
        let buf = self.buffer.read().unwrap();
        buf.lines.iter()
            .filter(|l| l.id > last_id)
            .cloned()
            .collect()
    }

    pub fn recent_lines(&self, n: usize) -> Vec<LogLine> {
        let buf = self.buffer.read().unwrap();
        buf.lines.iter()
            .rev()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.tx.subscribe()
    }
}

pub async fn tail_file(path: &str, tailer: Arc<LogTailer>) -> anyhow::Result<()> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        tailer.push(line.trim_end().to_string());
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "replay")]
    Replay { last_id: Option<u64>, count: Option<usize> },
    #[serde(rename = "pause")]
    Pause,
    #[serde(rename = "resume")]
    Resume,
}

#[utoipa::path(
    get,
    path = "/api/logs/ws",
    responses(
        (status = 101, description = "WebSocket upgrade"),
    ),
    description = "WebSocket endpoint for streaming log output. Sends JSON `{id, data}` frames. Accepts client commands: `{\"type\":\"replay\", \"last_id\": 0}`, `{\"type\":\"pause\"}`, `{\"type\":\"resume\"}`."
)]
pub async fn ws_logs(
    req: HttpRequest,
    body: web::Payload,
    tailer: web::Data<LogTailer>,
) -> actix_web::Result<HttpResponse> {
    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    let tailer: Arc<LogTailer> = tailer.into_inner();

    actix_web::rt::spawn(handle_websocket(tailer, session, msg_stream));

    Ok(response)
}

async fn handle_websocket(tailer: Arc<LogTailer>, mut session: Session, mut msg_stream: MessageStream) {
    // Send recent lines on connect
    if send_lines(&mut session, &tailer.recent_lines(100)).await.is_err() {
        return;
    }

    let mut rx = tailer.subscribe();
    let mut paused = false;

    loop {
        tokio::select! {
            Some(msg) = msg_stream.recv() => {
                match msg {
                    Ok(actix_ws::Message::Text(text)) => {
                        if let Err(()) = handle_client_message(
                            &text, &mut session, &tailer, &mut paused
                        ).await {
                            return;
                        }
                    }
                    Ok(actix_ws::Message::Ping(bytes)) => {
                        let _ = session.pong(&bytes).await;
                    }
                    Ok(actix_ws::Message::Close(_)) | Err(_) => return,
                    _ => {}
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(line) if !paused => {
                        if send_lines(&mut session, &[line]).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged, skipped {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// Send a batch of log lines as JSON text frames. Returns Err(()) if the session is closed.
async fn send_lines(session: &mut actix_ws::Session, lines: &[LogLine]) -> Result<(), ()> {
    for line in lines {
        let json = serde_json::to_string(line).unwrap();
        session.text(json).await.map_err(|_| ())?;
    }
    Ok(())
}

/// Parse and handle a client message. Returns Err(()) if the session should close.
async fn handle_client_message(
    text: &str,
    session: &mut actix_ws::Session,
    tailer: &LogTailer,
    paused: &mut bool,
) -> Result<(), ()> {
    let Ok(cmd) = serde_json::from_str::<ClientMessage>(text) else {
        tracing::warn!("User WS message is invalid");
        return Ok(());
    };
    match cmd {
        ClientMessage::Replay { last_id, count } => {
            tracing::info!("Received replay request");
            let lines = match last_id {
                Some(id) => tailer.lines_after(id),
                None => tailer.recent_lines(count.unwrap_or(100)),
            };
            send_lines(session, &lines).await?;
        }
        ClientMessage::Pause => *paused = true,
        ClientMessage::Resume => *paused = false,
    }
    Ok(())
}