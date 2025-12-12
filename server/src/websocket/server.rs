use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;

use crate::websocket::client::Client;

// WebSocket服务器状态
#[derive(Clone)]
pub struct WsServer {
    clients: Arc<Mutex<HashMap<String, Client>>>,
    broadcaster: broadcast::Sender<String>,
}

impl WsServer {
    // 创建新的WebSocket服务器
    pub fn new() -> Self {
        let (broadcaster, _) = broadcast::channel(100);
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            broadcaster,
        }
    }

    // 启动WebSocket服务器
    pub async fn start(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        println!("WebSocket server listening on {}", addr);

        while let Ok((stream, _)) = listener.accept().await {
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    eprintln!("Error handling connection: {}", e);
                }
            });
        }

        Ok(())
    }

    // 处理WebSocket连接
    async fn handle_connection(&self, stream: tokio::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let ws_stream = accept_async(stream).await?;
        let client_id = Uuid::new_v4().to_string();
        
        // 创建新客户端
        let client = Client::new(client_id.clone(), ws_stream, self.broadcaster.subscribe()).await;
        
        // 添加客户端到列表
        { 
            let mut clients = self.clients.lock().unwrap();
            // 使用自定义的clone方法
            let client_clone = client.clone();
            clients.insert(client_id.clone(), client_clone);
            println!("New client connected: {}", client_id);
        }
        
        // 广播新客户端连接
        self.broadcaster.send(format!("Client {} joined", client_id))?;
        
        // 处理客户端消息
        client.run().await;
        
        // 移除客户端
        { 
            let mut clients = self.clients.lock().unwrap();
            clients.remove(&client_id);
            println!("Client disconnected: {}", client_id);
        }
        
        // 广播客户端断开连接
        self.broadcaster.send(format!("Client {} left", client_id))?;
        
        Ok(())
    }
    
    // 发送消息给所有客户端
    pub fn broadcast(&self, message: &str) {
        if let Err(e) = self.broadcaster.send(message.to_string()) {
            eprintln!("Error broadcasting message: {}", e);
        }
    }
}