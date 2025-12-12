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

// 消息模型
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: String,          // UUID主键
    pub sender_id: String,   // 发送者ID
    pub receiver_id: String, // 接收者ID（用户或群聊）
    pub content: String,     // 消息内容
    pub message_type: String, // 消息类型："private"或"group"
    pub created_at: i64,     // 创建时间戳
    pub is_read: bool,       // 是否已读
}

// 好友关系模型
#[derive(Debug, Serialize, Deserialize)]
pub struct Friendship {
    pub id: String,          // UUID主键
    pub user_id: String,     // 用户ID
    pub friend_id: String,   // 好友ID
    pub status: String,      // 好友状态："pending"或"accepted"
    pub created_at: i64,     // 创建时间戳
}

// 群聊模型
#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub id: String,          // UUID主键
    pub name: String,        // 群聊名称
    pub creator_id: String,  // 创建者ID
    pub created_at: i64,     // 创建时间戳
}

// 群聊成员模型
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub id: String,          // UUID主键
    pub group_id: String,    // 群聊ID
    pub user_id: String,     // 用户ID
    pub joined_at: i64,      // 加入时间戳
    pub role: String,        // 角色："owner"或"member"
}

// 数据库连接池（线程安全）
#[derive(Clone)]
pub struct DbPool(pub Arc<Mutex<Connection>>);

impl DbPool {
    // 初始化数据库连接并创建所有表
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        
        // 创建表（若不存在）
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
        
        // 创建消息表
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                message_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(sender_id) REFERENCES users(id)
            )",
            [],
        )?;
        
        // 创建好友关系表
        conn.execute(
            "CREATE TABLE IF NOT EXISTS friendships (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                friend_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(friend_id) REFERENCES users(id),
                UNIQUE(user_id, friend_id)
            )",
            [],
        )?;
        
        // 创建群聊表
        conn.execute(
            "CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                creator_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(creator_id) REFERENCES users(id)
            )",
            [],
        )?;
        
        // 创建群聊成员表
        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_members (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                role TEXT NOT NULL,
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                UNIQUE(group_id, user_id)
            )",
            [],
        )?;
        
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    // 注册新用户（核心逻辑）
    pub fn register_user(
        &self,
        username: &str,
        _email: &str, // 保留参数但忽略，保持向后兼容
        password: &str,
    ) -> Result<User> {
        let conn = self.0.lock().unwrap();
        //检查用户名是否已存在
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)",
            params![username],
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
                "", // 邮箱字段设为空字符串
                password_hash,
                created_at
            ],
        )?;

        // 返回新用户（不含敏感信息）
        Ok(User {
            id: user_id,
            username: username.to_string(),
            email: "".to_string(), // 返回空邮箱
            password_hash,
            created_at,
        })
    }
    
    // 发送消息
    pub fn send_message(
        &self,
        sender_id: &str,
        receiver_id: &str,
        content: &str,
        message_type: &str,
    ) -> Result<Message> {
        let conn = self.0.lock().unwrap();
        
        let message_id = Uuid::new_v4().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        conn.execute(
            "INSERT INTO messages (id, sender_id, receiver_id, content, message_type, created_at, is_read) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message_id,
                sender_id,
                receiver_id,
                content,
                message_type,
                created_at,
                0 // 初始未读
            ],
        )?;
        
        Ok(Message {
            id: message_id,
            sender_id: sender_id.to_string(),
            receiver_id: receiver_id.to_string(),
            content: content.to_string(),
            message_type: message_type.to_string(),
            created_at,
            is_read: false,
        })
    }
    
    // 获取用户的未读消息
    pub fn get_unread_messages(&self, user_id: &str) -> Result<Vec<Message>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sender_id, receiver_id, content, message_type, created_at, is_read 
             FROM messages 
             WHERE receiver_id = ? AND is_read = 0 AND message_type = 'private'"
        )?;
        
        let messages = stmt.query_map([user_id], |row| {
            Ok(Message {
                id: row.get(0)?,
                sender_id: row.get(1)?,
                receiver_id: row.get(2)?,
                content: row.get(3)?,
                message_type: row.get(4)?,
                created_at: row.get(5)?,
                is_read: row.get(6)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
        
        Ok(messages)
    }
    
    // 将消息标记为已读
    pub fn mark_messages_as_read(&self, message_ids: &[String]) -> Result<()> {
        let conn = self.0.lock().unwrap();
        
        for message_id in message_ids {
            conn.execute(
                "UPDATE messages SET is_read = 1 WHERE id = ?",
                [message_id],
            )?;
        }
        
        Ok(())
    }
    
    // 获取用户好友列表
    pub fn get_friends(&self, user_id: &str) -> Result<Vec<User>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.username, u.email, u.password_hash, u.created_at 
             FROM users u 
             JOIN friendships f ON u.id = f.friend_id 
             WHERE f.user_id = ? AND f.status = 'accepted'"
        )?;
        
        let friends = stmt.query_map([user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
        
        Ok(friends)
    }
}