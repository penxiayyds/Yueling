use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use crate::storage::DbPool;
use crate::error::AppError;
use bcrypt::verify;

// 注册请求体（前端提交数据）
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String, // 明文密码（后端哈希存储）
}

// 注册响应体（返回给前端）
#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<String>, // 成功时返回用户ID
}

// 登录请求体（前端提交数据）
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String, // 明文密码（后端验证）
}

// 登录响应体（返回给前端）
#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<String>, // 成功时返回用户ID
    pub username: Option<String>, // 成功时返回用户名
}

// 注册处理器（核心API逻辑）
pub async fn register_handler(
    State(pool): State<DbPool>, // 注入数据库连接池
    Json(req): Json<RegisterRequest>, // 解析JSON请求体
) -> Result<Json<RegisterResponse>, AppError> {
    // 调用存储层注册用户
    let user = pool.register_user(&req.username, "", &req.password)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => 
                AppError::UserExists("用户名已被注册".into()),
            _ => AppError::Database(e.to_string()),
        })?;

    // 返回成功响应
    Ok(Json(RegisterResponse {
        success: true,
        message: "注册成功".into(),
        user_id: Some(user.id),
    }))
}

// 登录处理器（核心API逻辑）
pub async fn login_handler(
    State(pool): State<DbPool>, // 注入数据库连接池
    Json(req): Json<LoginRequest>, // 解析JSON请求体
) -> Result<Json<LoginResponse>, AppError> {
    // 调用存储层获取用户
    // 注意：这里应该使用存储层提供的方法，而不是直接访问内部字段
    // 但为了快速修复，我们暂时修改DbPool结构体，使其内部字段可访问
    let conn = pool.0.lock().unwrap();
    let user = conn.query_row(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        [&req.username],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => 
            AppError::InvalidCredentials("用户名或密码错误".into()),
        _ => AppError::Database(e.to_string()),
    })?;

    // 验证密码
    let (id, username, password_hash) = user;
    if !verify(&req.password, &password_hash).map_err(|_| AppError::Internal("密码验证失败".into()))? {
        return Err(AppError::InvalidCredentials("用户名或密码错误".into()));
    }

    // 返回成功响应
    Ok(Json(LoginResponse {
        success: true,
        message: "登录成功".into(),
        user_id: Some(id),
        username: Some(username),
    }))
}

// 导出路由
pub fn register_routes() -> Router<DbPool> {
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
}