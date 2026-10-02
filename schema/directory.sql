-- D1 只保存邮箱到账号的目录；安全状态仅在账号 SQLite Durable Object。
CREATE TABLE IF NOT EXISTS account_directory (email TEXT PRIMARY KEY, account_id TEXT UNIQUE NOT NULL);
