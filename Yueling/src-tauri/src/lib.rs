use std::sync::Arc;
use std::sync::Mutex;
use std::net::TcpStream;
use std::io::{Read, Write};

// 聊天客户端状态
struct ChatClient {
    tcp_stream: Option<TcpStream>,
    messages: Vec<String>,
    is_connected: bool,
    protocol: String,
}

impl Default for ChatClient {
    fn default() -> Self {
        Self {
            tcp_stream: None,
            messages: Vec::new(),
            is_connected: false,
            protocol: "tcp".to_string(),
        }
    }
}

// 全局状态
struct AppState {
    chat_client: Mutex<ChatClient>,
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn connect_to_server(state: tauri::State<'_, Arc<AppState>>, protocol: &str) -> Result<String, String> {
    // 先检查连接状态
    {
        let client = state.chat_client.lock().unwrap();
        if client.is_connected {
            return Err("Already connected".to_string());
        }
    }
    
    let (protocol_used, stream) = if protocol == "quic" {
        // 优先尝试QUIC连接
        match attempt_quic_connection().await {
            Ok(_) => {
                // 模拟QUIC连接成功
                ("quic", None)
            },
            Err(quic_err) => {
                // QUIC连接失败，尝试TCP
                println!("QUIC connection failed: {}, trying TCP", quic_err);
                match connect_tcp() {
                    Ok(stream) => ("tcp", Some(stream)),
                    Err(tcp_err) => return Err(format!("Both QUIC and TCP connection failed: QUIC: {}, TCP: {}", quic_err, tcp_err))
                }
            }
        }
    } else {
        // 直接使用TCP
        match connect_tcp() {
            Ok(stream) => ("tcp", Some(stream)),
            Err(e) => return Err(e)
        }
    };
    
    // 更新连接状态
    {
        let mut client = state.chat_client.lock().unwrap();
        client.is_connected = true;
        client.protocol = protocol_used.to_string();
        if let Some(stream) = stream {
            client.tcp_stream = Some(stream);
        }
    }
    
    Ok(format!("Connected via {}", protocol_used))
}

#[tauri::command]
async fn send_message(state: tauri::State<'_, Arc<AppState>>, message: &str) -> Result<String, String> {
    // 获取当前连接状态
    let protocol = {
        let client = state.chat_client.lock().unwrap();
        if !client.is_connected {
            return Err("Not connected to server".to_string());
        }
        client.protocol.clone()
    };
    
    // 发送消息
    let response = if protocol == "quic" {
        // 模拟QUIC发送消息
        send_quic_message(message).await
    } else {
        // 使用TCP发送消息
        let mut stream = {
            let mut client = state.chat_client.lock().unwrap();
            client.tcp_stream.take()
        };
        
        if let Some(ref mut s) = stream {
            let result = send_tcp_message(s, message);
            
            // 归还流
            let mut client = state.chat_client.lock().unwrap();
            client.tcp_stream = stream;
            
            result
        } else {
            Err("TCP connection not established".to_string())
        }
    };
    
    // 更新消息列表
    match response {
        Ok(response) => {
            let mut client = state.chat_client.lock().unwrap();
            client.messages.push(format!("You: {}", message));
            client.messages.push(format!("Server: {}", response));
            Ok(response)
        },
        Err(e) => Err(e),
    }
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut client = state.chat_client.lock().unwrap();
    
    if !client.is_connected {
        return Err("Not connected to server".to_string());
    }
    
    // 断开连接逻辑
    client.tcp_stream.take();
    client.is_connected = false;
    
    Ok("Disconnected".to_string())
}

#[tauri::command]
fn get_messages(state: tauri::State<'_, Arc<AppState>>) -> Vec<String> {
    let client = state.chat_client.lock().unwrap();
    client.messages.clone()
}

// 尝试QUIC连接（模拟实现）
async fn attempt_quic_connection() -> Result<(), String> {
    // 模拟QUIC连接尝试
    println!("Attempting QUIC connection...");
    
    // 这里可以添加实际的QUIC连接代码
    // 目前返回错误，让客户端回退到TCP
    Err("QUIC not implemented yet, falling back to TCP".to_string())
}

// 模拟QUIC发送消息
async fn send_quic_message(message: &str) -> Result<String, String> {
    // 模拟QUIC消息发送
    println!("Sending QUIC message: {}", message);
    Ok(format!("Echo: {}", message))
}

// TCP连接函数
fn connect_tcp() -> Result<TcpStream, String> {
    // 连接到TCP服务器
    let stream = TcpStream::connect("127.0.0.1:2025")
        .map_err(|e| format!("Failed to connect to TCP server: {}", e))?;
    
    println!("TCP connection established");
    Ok(stream)
}

// TCP发送消息函数
fn send_tcp_message(stream: &mut TcpStream, message: &str) -> Result<String, String> {
    // 发送消息
    stream.write_all(message.as_bytes())
        .map_err(|e| format!("Failed to send TCP message: {}", e))?;
    
    // 接收响应
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer)
        .map_err(|e| format!("Failed to read TCP response: {}", e))?;
    
    Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = Arc::new(AppState {
        chat_client: Mutex::new(ChatClient::default()),
    });
    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            greet,
            connect_to_server,
            send_message,
            disconnect,
            get_messages
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
