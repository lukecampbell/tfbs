use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
    time::Duration,
};

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::{MessageStream, Session};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::{fs::File, sync::broadcast};

use crate::error::AppError;

/// A single line of tailed log output, tagged with a monotonically increasing
/// id so clients can request replays of anything they've missed.
#[derive(Clone, Serialize)]
pub struct LogLine {
    pub id: u64,
    pub data: String,
}

/// In-memory log tailer: retains a bounded ring buffer of recent lines and
/// fans new lines out to WebSocket subscribers via a Tokio broadcast channel.
pub struct LogTailer {
    tx: broadcast::Sender<LogLine>,
    buffer: Arc<RwLock<RingBuffer>>,
}

/// Fixed-size ring buffer of log lines. Oldest entries are evicted once
/// `max_size` is reached. `next_id` is never reset so ids stay unique for the
/// lifetime of the tailer.
struct RingBuffer {
    lines: VecDeque<LogLine>,
    max_size: usize,
    next_id: u64,
}

impl LogTailer {
    /// Create a new tailer that retains the most recent `buffer_size` lines.
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

    /// Append a line to the ring buffer and broadcast it to all subscribers.
    ///
    /// Evicts the oldest line if the buffer is full. Broadcast send errors
    /// (no live receivers) are intentionally ignored.
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

    /// Return every buffered line whose id is strictly greater than `last_id`.
    /// Used to service client "replay since id N" requests.
    pub fn lines_after(&self, last_id: u64) -> Vec<LogLine> {
        let buf = self.buffer.read().unwrap();
        buf.lines
            .iter()
            .filter(|l| l.id > last_id)
            .cloned()
            .collect()
    }

    /// Return the most recent `n` buffered lines in chronological order.
    pub fn recent_lines(&self, n: usize) -> Vec<LogLine> {
        let buf = self.buffer.read().unwrap();
        buf.lines
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Subscribe to new lines appended after this call. Existing buffer
    /// contents must be fetched separately via [`Self::recent_lines`] or
    /// [`Self::lines_after`].
    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.tx.subscribe()
    }
}

/// Follow a file on disk (à la `tail -f`) and forward new lines to `tailer`.
///
/// When EOF is reached the loop sleeps 100ms and retries. Every ~5 seconds of
/// consecutive idle polls (50 iterations) it re-stats the path and exits
/// cleanly if the file has been removed — this is how an orphaned tailer
/// task gets reaped when its source file disappears. Any other IO error
/// propagates out.
pub async fn tail_file(path: &str, tailer: Arc<LogTailer>) -> anyhow::Result<()> {
    let path = std::path::Path::new(path);
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut check_counter: u32 = 0;
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            // EOF — wait a beat and try again. Periodically verify the file
            // still exists so we don't poll a deleted file forever.
            check_counter += 1;
            // Check every ~5 seconds (50 * 100ms)
            if check_counter >= 50 {
                check_counter = 0;
                if !path.exists() {
                    tracing::info!("File {} no longer exists, stopping tailer", path.display());
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        check_counter = 0;
        tailer.push(line.trim_end().to_string());
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "replay")]
    Replay {
        last_id: Option<u64>,
        count: Option<usize>,
    },
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
/// HTTP handler: upgrade an authenticated request to a WebSocket for streaming
/// log output.
///
/// The path segment `file_id` is looked up in Redis to resolve the actual
/// file path on disk. A fresh [`LogTailer`] and background `tail_file` task
/// are spawned per connection; the WebSocket loop runs under
/// `actix_web::rt::spawn`. Returns 401 if the session is unauthenticated and
/// 404 if the file id is unknown.
pub async fn ws_logs(
    req: HttpRequest,
    body: web::Payload,
    session: actix_session::Session,
    redis: web::Data<redis::Client>,
    file_id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let Ok(Some(_user)) = session.get::<crate::data::User>("user") else {
        return Ok(HttpResponse::Unauthorized().finish());
    };
    tracing::info!("New logtail request");
    let (response, session, msg_stream) = actix_ws::handle(&req, body)?;
    let mut redis_conn = redis
        .get_multiplexed_async_connection()
        .await
        .map_err(AppError::RedisError)?;
    let Some(file_path): Option<String> = redis::cmd("GET")
        .arg(&*file_id)
        .query_async(&mut redis_conn)
        .await
        .map_err(AppError::RedisError)?
    else {
        tracing::error!("No file available for file_id={file_id}");
        return Ok(HttpResponse::NotFound().finish());
    };
    let tailer: Arc<LogTailer> = Arc::new(LogTailer::new(10_000));
    let worker_tailer = tailer.clone();
    tokio::spawn(async move {
        tracing::info!("Tailing new file: {file_path}");
        if let Err(e) = tail_file(&file_path, worker_tailer).await {
            tracing::error!("Log tailer failed: {e}");
        }
    });

    actix_web::rt::spawn(handle_websocket(tailer, session, msg_stream));

    Ok(response)
}

/// Drive a single WebSocket connection for the lifetime of the client.
///
/// On connect, the 100 most recent buffered lines are replayed. The loop then
/// multiplexes two sources:
///
/// - Inbound client messages (`replay`, `pause`, `resume`, plus Ping/Close).
/// - Outbound log lines from the broadcast receiver, skipped when `paused`.
///
/// If the broadcast channel lags, the lag is logged and streaming resumes
/// from the next available line — clients can call `replay` to backfill any
/// skipped ids. Any send error or a client close terminates the task.
async fn handle_websocket(
    tailer: Arc<LogTailer>,
    mut session: Session,
    mut msg_stream: MessageStream,
) {
    // Send recent lines on connect
    if send_lines(&mut session, &tailer.recent_lines(100))
        .await
        .is_err()
    {
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
