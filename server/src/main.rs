mod api;
mod storage;
mod error;
use storage::DbPool;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::{CorsLayer, Any};
use axum::http::Method;

#[tokio::main] // 异步运行时（tokio full特性已启用）
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化数据库
    let db_pool = DbPool::new("server.db")?;

    // 构建API路由
    // 添加 CORS 层以允许浏览器前端跨域请求（处理 OPTIONS 预检）
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    let app = api::register_routes(db_pool.clone()).layer(cors);

    // 启动统一服务器，使用单个端口
    let port = 2025;
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Server listening on http://{} (TCP) and ws://{} (WebSocket)", addr, addr);
    
    // 使用axum的正确方式启动服务器
    axum::serve(listener, app).await?;
    
    Ok(())
}
