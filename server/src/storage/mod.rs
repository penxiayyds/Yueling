use rusqlite::{params, Connection, Result};
use bcrypt::{hash, DEFAULT_COST};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};

// 用户模型（对应数据库表）
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,          // UUID主键
    pub username: String,    // 用户名（唯一）
    pub email: String,       // 邮箱（唯一）
    pub password_hash: String, // bcrypt哈希后的密码
    pub created_at: i64,     // 创建时间戳（Unix秒）
}

// 数据库连接池（线程安全）
#[derive(Clone)]
pub struct DbPool(Arc<Mutex<Connection>>);

impl DbPool {
    // 初始化数据库连接并创建用户表
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        // 创建用户表（若不存在）
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    // 注册新用户（核心逻辑）
    pub fn register_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<User> {
        let conn = self.0.lock().unwrap();
        //检查用户名/邮箱是否已存在
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)",
            params![username, email],
            |row| row.get(0),
        )?;
        if exists {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }

        //密码哈希（bcrypt）
        let password_hash = hash(password, DEFAULT_COST).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;

        //插入数据库
        let user_id = Uuid::new_v4().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO users (id, username, email, password_hash, created_at) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                user_id,
                username,
                email,
                password_hash,
                created_at
            ],
        )?;

        // 返回新用户（不含敏感信息）
        Ok(User {
            id: user_id,
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            created_at,
        })
    }
}