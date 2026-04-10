const express = require('express');
const db = require('./database.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'restaurant-system-secret-key-2026';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// ========== 辅助函数 ==========
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未提供认证令牌' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '令牌无效或已过期' });
    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '需要超级管理员权限' });
  next();
}

function managerOrSubuser(req, res, next) {
  if (req.user.role === 'admin') return res.status(403).json({ error: '超级管理员不能访问店长功能' });
  if (req.user.role !== 'manager' && req.user.role !== 'subuser') {
    return res.status(403).json({ error: '权限不足' });
  }
  if (req.user.role === 'subuser') {
    db.get('SELECT manager_id FROM users WHERE id = ?', [req.user.id], (err, row) => {
      if (err || !row) return res.status(403).json({ error: '无效的子账号' });
      req.manager_id = row.manager_id;
      req.isSubuser = true;
      next();
    });
  } else {
    req.manager_id = req.user.id;
    req.isSubuser = false;
    next();
  }
}

// ========== 公共API（顾客端） ==========
app.get('/api/menu/:managerUsername', (req, res) => {
  const { managerUsername } = req.params;
  db.get('SELECT id FROM users WHERE username = ? AND role = "manager" AND is_active = 1', [managerUsername], (err, manager) => {
    if (err || !manager) return res.status(404).json({ error: '店家不存在或未启用' });
    db.all('SELECT * FROM menu_items WHERE manager_id = ? AND is_available = 1 ORDER BY category', [manager.id], (err, items) => {
      if (err) return res.status(500).json({ error: err.message });
      items.forEach(item => { if (item.size_options) item.size_options = JSON.parse(item.size_options); });
      res.json({ managerId: manager.id, items });
    });
  });
});

// 顾客端获取店家信息（含地图、电话、LINE）
app.get('/api/store-info/:managerUsername', (req, res) => {
  const { managerUsername } = req.params;
  db.get(`SELECT u.id, s.logo_url, s.restaurant_name, s.background_image_url, s.map_url, s.phone, s.line_url 
          FROM users u LEFT JOIN store_settings s ON u.id = s.manager_id 
          WHERE u.username = ? AND u.role = 'manager' AND u.is_active = 1`, [managerUsername], (err, info) => {
    if (err || !info) return res.status(404).json({ error: '店家不存在' });
    res.json(info);
  });
});

app.post('/api/orders', (req, res) => {
  const { manager_id, customer_name, customer_phone, items, total_amount, note } = req.body;
  if (!manager_id || !customer_name || !customer_phone || !items || !total_amount) {
    return res.status(400).json({ error: '缺少必要字段' });
  }
  db.run(`INSERT INTO orders (manager_id, customer_name, customer_phone, items, total_amount, note, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
    [manager_id, customer_name, customer_phone, JSON.stringify(items), total_amount, note || ''], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, message: '订单提交成功' });
    });
});

// ========== 认证API ==========
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: '用户名或密码错误' });
    if (user.is_active !== 1) return res.status(401).json({ error: '账号已被停权，请联系超级管理员' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: '用户名或密码错误' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });
});

// 注册（增加 email 字段）
app.post('/api/auth/register', async (req, res) => {
  const { username, password, email, restaurant_name, logo_url, background_image_url } = req.body;
  if (!username || !password || !email) return res.status(400).json({ error: '用户名、密码和邮箱不能为空' });
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) return res.status(400).json({ error: '邮箱格式不正确' });
  
  db.get('SELECT id FROM users WHERE username = ?', [username], async (err, exist) => {
    if (err) return res.status(500).json({ error: err.message });
    if (exist) return res.status(400).json({ error: '用户名已存在' });
    const hashedPwd = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, email, role, is_active) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPwd, email, 'manager', 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        const manager_id = this.lastID;
        db.run(`INSERT INTO store_settings (manager_id, logo_url, restaurant_name, background_image_url) VALUES (?, ?, ?, ?)`,
          [manager_id, logo_url || '', restaurant_name || '', background_image_url || '']);
        res.status(201).json({ message: '注册成功，请等待超级管理员审核' });
      });
  });
});

// ========== 忘记密码 API（验证帐号+信箱，直接返回 token） ==========
app.post('/api/auth/forgot-password', async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    return res.status(400).json({ error: '请提供帐号和电子信箱' });
  }

  db.get('SELECT id FROM users WHERE username = ? AND email = ? AND role = "manager"', [username, email], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) {
      return res.status(400).json({ error: '帐号与信箱不匹配' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 小时有效
    db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, expires, user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ token });
    });
  });
});

// ========== 重置密码 API ==========
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: '缺少必要参数' });
  if (newPassword.length < 4) return res.status(400).json({ error: '密码长度至少4码' });
  
  db.get('SELECT id FROM users WHERE reset_token = ? AND reset_expires > ?', [token, Date.now()], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: '无效或已过期的重置链接' });
    const hashedPwd = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', [hashedPwd, user.id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: '密码已成功重置，请重新登录' });
    });
  });
});

// ========== 超级管理员API ==========
app.get('/api/admin/managers', authenticateToken, adminOnly, (req, res) => {
  db.all(`SELECT u.id, u.username, u.is_active, u.created_at, s.restaurant_name, s.logo_url, s.background_image_url 
          FROM users u LEFT JOIN store_settings s ON u.id = s.manager_id WHERE u.role = 'manager' ORDER BY u.created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.put('/api/admin/managers/:id/approve', authenticateToken, adminOnly, (req, res) => {
  db.run('UPDATE users SET is_active = 1 WHERE id = ? AND role = "manager"', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '店长已通过审核' });
  });
});

app.put('/api/admin/managers/:id/suspend', authenticateToken, adminOnly, (req, res) => {
  db.run('UPDATE users SET is_active = 0 WHERE id = ? AND role = "manager"', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '店长已停权' });
  });
});

app.get('/api/admin/bank-info', authenticateToken, adminOnly, (req, res) => {
  db.get('SELECT bank_info FROM global_bank_info WHERE id = 1', (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ bank_info: row ? row.bank_info : '' });
  });
});

app.put('/api/admin/bank-info', authenticateToken, adminOnly, (req, res) => {
  const { bank_info } = req.body;
  if (!bank_info) return res.status(400).json({ error: '银行信息不能为空' });
  db.run('UPDATE global_bank_info SET bank_info = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1', [bank_info], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '银行信息已更新' });
  });
});

// ========== 缴费记录（超管） ==========
app.get('/api/admin/payments', authenticateToken, adminOnly, (req, res) => {
  db.all(`SELECT p.*, u.username as manager_username, s.restaurant_name 
          FROM payment_records p
          JOIN users u ON p.manager_id = u.id
          LEFT JOIN store_settings s ON u.id = s.manager_id
          ORDER BY p.created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.put('/api/admin/payments/:id/confirm', authenticateToken, adminOnly, (req, res) => {
  db.run(`UPDATE payment_records SET status = 'confirmed', confirmed_at = CURRENT_TIMESTAMP WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: '纪录不存在' });
    res.json({ message: '已确认收款' });
  });
});

// ========== 店长及子账号API ==========
// 获取店长设置（含地图、电话、LINE）
app.get('/api/manager/settings', authenticateToken, managerOrSubuser, (req, res) => {
  db.get('SELECT logo_url, restaurant_name, background_image_url, map_url, phone, line_url FROM store_settings WHERE manager_id = ?', [req.manager_id], (err, settings) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(settings || {});
  });
});

// 修改店长设置（只有店长可以）
app.put('/api/manager/settings', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以修改设置' });
  next();
}, managerOrSubuser, (req, res) => {
  const { logo_url, restaurant_name, background_image_url, map_url, phone, line_url } = req.body;
  db.run(`UPDATE store_settings SET 
            logo_url = ?, restaurant_name = ?, background_image_url = ?, 
            map_url = ?, phone = ?, line_url = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE manager_id = ?`,
    [logo_url || '', restaurant_name || '', background_image_url || '', map_url || '', phone || '', line_url || '', req.manager_id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: '店铺设置已更新' });
    });
});

app.get('/api/manager/menu', authenticateToken, managerOrSubuser, (req, res) => {
  db.all('SELECT * FROM menu_items WHERE manager_id = ? ORDER BY category', [req.manager_id], (err, items) => {
    if (err) return res.status(500).json({ error: err.message });
    items.forEach(item => { if (item.size_options) item.size_options = JSON.parse(item.size_options); });
    res.json(items);
  });
});

app.post('/api/manager/menu', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以新增菜品' });
  next();
}, managerOrSubuser, (req, res) => {
  const { name, image_url, size_options, price, description, category } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: '菜品名称和价格不能为空' });
  const sizeJson = size_options ? JSON.stringify(size_options) : null;
  db.run(`INSERT INTO menu_items (manager_id, name, image_url, size_options, price, description, category) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.manager_id, name, image_url || '', sizeJson, price, description || '', category || '其他'], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, message: '菜品添加成功' });
    });
});

app.put('/api/manager/menu/:id', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以修改菜品' });
  next();
}, managerOrSubuser, (req, res) => {
  const { id } = req.params;
  const { name, image_url, size_options, price, description, category, is_available } = req.body;
  const sizeJson = size_options ? JSON.stringify(size_options) : null;
  db.run(`UPDATE menu_items SET name = ?, image_url = ?, size_options = ?, price = ?, description = ?, category = ?, is_available = ? WHERE id = ? AND manager_id = ?`,
    [name, image_url, sizeJson, price, description, category, is_available !== undefined ? is_available : 1, id, req.manager_id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: '菜品更新成功' });
    });
});

app.delete('/api/manager/menu/:id', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以删除菜品' });
  next();
}, managerOrSubuser, (req, res) => {
  db.run('DELETE FROM menu_items WHERE id = ? AND manager_id = ?', [req.params.id, req.manager_id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '菜品删除成功' });
  });
});

app.get('/api/manager/orders', authenticateToken, managerOrSubuser, (req, res) => {
  db.all('SELECT * FROM orders WHERE manager_id = ? ORDER BY created_at DESC', [req.manager_id], (err, orders) => {
    if (err) return res.status(500).json({ error: err.message });
    orders.forEach(order => { order.items = JSON.parse(order.items); });
    res.json(orders);
  });
});

// ✅ 修改：允许子账号更新订单状态（移除角色限制，只保留身份验证和所属店长验证）
app.put('/api/manager/orders/:id/status', authenticateToken, managerOrSubuser, (req, res) => {
  const { status } = req.body;
  if (!['pending', 'accepted', 'completed', 'cancelled'].includes(status)) return res.status(400).json({ error: '无效状态' });
  db.run('UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND manager_id = ?', [status, req.params.id, req.manager_id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '订单状态已更新' });
  });
});

app.get('/api/manager/daily-sales', authenticateToken, managerOrSubuser, (req, res) => {
  const { date } = req.query;
  let dateCondition = "date(created_at) = date('now')";
  if (date) dateCondition = `date(created_at) = '${date}'`;
  db.get(`SELECT SUM(total_amount) as total FROM orders WHERE manager_id = ? AND status IN ('accepted','completed') AND ${dateCondition}`, [req.manager_id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ total: row.total || 0, date: date || new Date().toISOString().slice(0,10) });
  });
});

app.get('/api/manager/subusers', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以管理子账号' });
  next();
}, managerOrSubuser, (req, res) => {
  db.all('SELECT id, username, created_at FROM users WHERE role = "subuser" AND manager_id = ?', [req.manager_id], (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users);
  });
});

app.post('/api/manager/subusers', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以创建子账号' });
  next();
}, managerOrSubuser, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  db.get('SELECT COUNT(*) as count FROM users WHERE role = "subuser" AND manager_id = ?', [req.manager_id], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row.count >= 3) return res.status(400).json({ error: '子账号最多只能创建3个' });
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, exist) => {
      if (err) return res.status(500).json({ error: err.message });
      if (exist) return res.status(400).json({ error: '用户名已存在' });
      const hashedPwd = await bcrypt.hash(password, 10);
      db.run('INSERT INTO users (username, password, role, manager_id, is_active) VALUES (?, ?, ?, ?, ?)', [username, hashedPwd, 'subuser', req.manager_id, 1], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, username, message: '子账号创建成功' });
      });
    });
  });
});

app.delete('/api/manager/subusers/:id', authenticateToken, (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以删除子账号' });
  next();
}, managerOrSubuser, (req, res) => {
  db.run('DELETE FROM users WHERE id = ? AND role = "subuser" AND manager_id = ?', [req.params.id, req.manager_id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: '子账号已删除' });
  });
});

app.get('/api/manager/bank-info', authenticateToken, managerOrSubuser, (req, res) => {
  db.get('SELECT bank_info FROM global_bank_info WHERE id = 1', (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ bank_info: row ? row.bank_info : '' });
  });
});

// ========== 店长缴费记录 API ==========
app.post('/api/manager/payments', authenticateToken, managerOrSubuser, (req, res) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: '只有店长可以新增缴费纪录' });
  const { date, amount, account_last5 } = req.body;
  if (!date || !amount || !account_last5) return res.status(400).json({ error: '日期、金额、账号后五码为必填' });
  db.run(`INSERT INTO payment_records (manager_id, date, amount, account_last5, status) VALUES (?, ?, ?, ?, 'pending')`,
    [req.manager_id, date, amount, account_last5], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, message: '缴费纪录已新增，等待管理员确认' });
    });
});

app.get('/api/manager/payments', authenticateToken, managerOrSubuser, (req, res) => {
  db.all(`SELECT * FROM payment_records WHERE manager_id = ? ORDER BY created_at DESC`, [req.manager_id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
  console.log(`顾客点餐页面: http://localhost:${PORT}/order.html?store=店长用户名`);
  console.log(`店长后台: http://localhost:${PORT}/manager.html`);
  console.log(`超级管理员后台: http://localhost:${PORT}/admin.html`);
});