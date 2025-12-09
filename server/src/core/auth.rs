use bcrypt::{hash, DEFAULT_COST};
use uuid::Uuid;
use anyhow::{Context, Result};
use crate::core::models::User;
use crate::storage::user::create_user;

//注册逻辑
pub async fn register_user(
     db_conn: &rusqlite::Connection  //数据库连接
     username: String,
     email: String,
     password: String,
)  -> Result<User> {
     if username.trim().is_empty() || email.trim().is_empty() || password.len() < 8 {
     }
     
     //检查用户名，邮箱是否重复 
     //先省略掉，到后面再补
     //密码哈希值
     let password_hash = hash(password, DEFAULT_COST)
        .context("密码哈希值失败")?;
     //生成uuid   
     let user_id = Uuid::new_v4().to_string(),
     //构造User对象
     let new_user = User {
         id: user_id,
         username: username.trim().to_string(),
         email: email.trim().to_lowercase(),
         password_hash,
     };
     //存入数据库
     tokio::task::spawn_blocking({
         let conn = db_conn.clone();
         move || create_user(&conn, &new_user)
     })
     .await??;
     
    Ok(new_user)
}