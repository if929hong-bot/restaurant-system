const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'restaurant.db');
const db = new sqlite3.Database(DB_PATH);

db.run('PRAGMA foreign_keys = ON');

db.serialize(() => {
  // 用户表（已有 email, reset_token, reset_expires）
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    reset_token TEXT,
    reset_expires INTEGER,
    role TEXT NOT NULL CHECK(role IN ('admin', 'manager', 'subuser')),
    manager_id INTEGER,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 店长专属设置表（增加三個欄位）
  db.run(`CREATE TABLE IF NOT EXISTS store_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_id INTEGER UNIQUE NOT NULL,
    logo_url TEXT,
    restaurant_name TEXT,
    background_image_url TEXT,
    bank_info TEXT,
    map_url TEXT,
    phone TEXT,
    line_url TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE
  )`, (err) => {
    if (!err) {
      // 嘗試增加新欄位（若已存在則忽略錯誤）
      db.run("ALTER TABLE store_settings ADD COLUMN map_url TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('map_url 欄位已存在'); });
      db.run("ALTER TABLE store_settings ADD COLUMN phone TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('phone 欄位已存在'); });
      db.run("ALTER TABLE store_settings ADD COLUMN line_url TEXT", (err) => { if (err && !err.message.includes('duplicate')) console.log('line_url 欄位已存在'); });
    }
  });

  // 菜单表
  db.run(`CREATE TABLE IF NOT EXISTS menu_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    image_url TEXT,
    size_options TEXT,
    price REAL NOT NULL,
    description TEXT,
    category TEXT,
    is_available INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 订单表
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_id INTEGER NOT NULL,
    customer_name TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    items TEXT NOT NULL,
    total_amount REAL NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'completed', 'cancelled')),
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 全局银行信息表
  db.run(`CREATE TABLE IF NOT EXISTS global_bank_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    bank_info TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (!err) {
      db.get('SELECT id FROM global_bank_info WHERE id = 1', (err, row) => {
        if (!err && !row) {
          db.run('INSERT INTO global_bank_info (id, bank_info) VALUES (1, ?)',
            ['银行：XX银行 帐号：1234-5678-9012 户名：XX餐饮管理有限公司']);
        }
      });
    }
  });

  // 缴费记录表
  db.run(`CREATE TABLE IF NOT EXISTS payment_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    amount REAL NOT NULL,
    account_last5 TEXT NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    confirmed_at DATETIME,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 默认超级管理员
  db.get('SELECT id FROM users WHERE role = "admin"', async (err, row) => {
    if (!err && !row) {
      const hashedPwd = await bcrypt.hash('rs0975521219', 10);
      db.run('INSERT INTO users (username, password, role, is_active) VALUES (?, ?, ?, ?)',
        ['0975521219', hashedPwd, 'admin', 1]);
    }
  });
});

module.exports = db;