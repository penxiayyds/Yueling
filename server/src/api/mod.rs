use axum::{Router};

// 导入子模块
mod user;
mod friend;
mod message;
mod ws;

// 重新导出AppState，以便其他模块可以通过super::AppState导入
pub use ws::AppState;

/// 注册所有API路由
pub fn register_routes(db_pool: crate::storage::DbPool) -> Router {
    // 创建共享应用状态
    let app_state = ws::AppState::new(db_pool);
    
    // 主路由器配置
    Router::new()
        // WebSocket路由
        .merge(ws::register_ws_route())
        // 用户相关路由
        .merge(user::register_routes())
        // 好友相关路由
        .merge(friend::register_routes())
        // 消息相关路由
        .merge(message::register_routes())
        .with_state(app_state)
}
