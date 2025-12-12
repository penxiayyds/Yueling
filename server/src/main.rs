mod api;
mod storage;
mod error;
mod websocket;
use storage::DbPool;
use axum::{Router, extract::State, response::Json};
use tokio::net::TcpListener;
use std::sync::Arc;
use websocket::WsServer;

#[tokio::main] // 异步运行时（tokio full特性已启用）
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化数据库
    let db_pool = DbPool::new("server.db")?;

    // 构建API路由
    let app = Router::new()
        .merge(api::register_routes()) // 注册路由
        .with_state(db_pool.clone());

    // 启动API服务器
    let api_port = 2025;
    let api_addr = format!("0.0.0.0:{}", api_port);
    let api_listener = TcpListener::bind(&api_addr).await?;
    println!("API server listening on http://{}", api_addr);
    
    tokio::spawn(async move {
        axum::serve(api_listener, app).await.unwrap();
    });

    // 启动WebSocket服务器
    let ws_server = WsServer::new();
    let ws_port = 2026;
    let ws_addr = format!("0.0.0.0:{}", ws_port);
    println!("WebSocket server listening on ws://{}", ws_addr);
    
    tokio::spawn(async move {
        if let Err(e) = ws_server.start(&ws_addr).await {
            eprintln!("WebSocket server error: {}", e);
        }
    });

    // 保持主线程运行
    println!("Server started successfully!");
    tokio::signal::ctrl_c().await?;
    println!("Server shutting down...");
    
    Ok(())
}
