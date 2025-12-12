use std::sync::Arc;
use tokio::sync::broadcast;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use tokio::net::TcpStream;

// WebSocket客户端
pub struct Client {
    id: String,
    ws_stream: Arc<tokio::sync::Mutex<WebSocketStream<TcpStream>>>,
    rx: broadcast::Receiver<String>,
}

impl Client {
    // 实现Clone trait，使用resubscribe获取新的接收器
    pub fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            ws_stream: self.ws_stream.clone(),
            rx: self.rx.resubscribe(),
        }
    }
}

impl Client {
    // 创建新客户端
    pub async fn new(
        id: String,
        ws_stream: WebSocketStream<TcpStream>,
        rx: broadcast::Receiver<String>,
    ) -> Self {
        Self {
            id,
            ws_stream: Arc::new(tokio::sync::Mutex::new(ws_stream)),
            rx,
        }
    }

    // 运行客户端消息处理循环
    pub async fn run(&self) {
        let mut rx = self.rx.resubscribe();
        let ws_stream = self.ws_stream.clone();
        let client_id = self.id.clone();

        // 处理接收到的消息
        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                let mut stream = ws_stream.lock().await;
                if let Err(e) = stream.send(Message::Text(msg.into())).await {
                    eprintln!("Error sending message to client {}: {}", client_id, e);
                    break;
                }
            }
        });

        // 处理来自客户端的消息
        let mut stream = self.ws_stream.lock().await;
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    println!("Received message from client {}: {}", self.id, text);
                    // 这里可以添加消息处理逻辑，比如解析消息类型，存储到数据库等
                }
                Ok(Message::Close(_)) => {
                    println!("Client {} closed connection", self.id);
                    break;
                }
                Err(e) => {
                    eprintln!("Error receiving message from client {}: {}", self.id, e);
                    break;
                }
                _ => {}
            }
        }
    }
}