use axum::{
     extract::State,
     Json,
     http::StatusCode,
     response::IntoResponse
};
use serde::{Deserialize, Serialize};
use crate::core::auth::register_user;
use crate::core::models::User;
use crate::state::AppState;

//注册请求参数
#[derive(Deserialize)]
pub state RegisterReq {
     pub username: String,
     pub email: String,
     pub password: String,
}
//注册响应
#[derive(Serialize)]
pub state RegisterReq {
     pub id: String,
     pub username: String,
     pub email: String,
}
//注册接口处理函数
pub async fn register_handler(
     State(state): State<AppState>,
     Json(reg): Json<RegisterReq>
)  ->  impl IntoResponse {
     match register_user(&state.db_conn, req.username, req.email, req.password).await {
          Ok(user) => {
               let resp = RegisterResp {
                   id: user.id,
                   username: user.username,
                   email: user.email
               };
               (StatusCode::CREATED, Json(resp))
          }
          Err(e) => {
              (StatusCode::BAD_REQUEST, e.to_string()).into_response()
          }
     }
}