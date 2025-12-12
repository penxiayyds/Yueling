use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("用户已存在: {0}")]
    UserExists(String),
    #[error("数据库错误: {0}")]
    Database(String),
    #[error("密码哈希失败: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("无效的凭证: {0}")]
    InvalidCredentials(String),
    #[error("内部服务器错误: {0}")]
    Internal(String),
}

// 实现axum的错误转换
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::UserExists(e) => (StatusCode::CONFLICT, e),
            AppError::Database(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            AppError::Bcrypt(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::InvalidCredentials(e) => (StatusCode::UNAUTHORIZED, e),
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        let body = Json(json!({ "success": false, "message": msg }));
        (status, body).into_response()
    }
}