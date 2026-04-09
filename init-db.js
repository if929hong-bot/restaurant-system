const db = require('./database.js');
const bcrypt = require('bcryptjs');

// 等待数据库表创建完成（简单延时）
setTimeout(() => {
  initData();
}, 1000);

async function initData() {
  // 不再插入任何示例店长或菜单数据，只保留超管（已在 database.js 中自动创建）
  console.log('数据库初始化完成（无示例数据）');
  setTimeout(() => {
    db.close();
  }, 500);
}