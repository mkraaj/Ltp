#!/usr/bin/env node
const readline = require('node:readline/promises');
const { stdin: input, stdout: output } = require('node:process');
const { openDatabase, id, now, hashPassword, closeDatabase } = require('../database');

function validEmail(email) { return /^\S+@\S+\.\S+$/.test(email); }
async function ask(name, secret = false) {
  if (!process.stdin.isTTY || process.env[name]) return process.env[name] || '';
  const rl = readline.createInterface({ input, output });
  const value = await rl.question(`${name}: `);
  rl.close();
  return value.trim();
}
(async () => {
  const email = (await ask('ADMIN_EMAIL')).toLowerCase();
  const password = await ask('ADMIN_PASSWORD', true);
  const name = (await ask('ADMIN_NAME')) || 'Administrator';
  if (!validEmail(email) || password.length < 12 || password.length > 256) {
    console.error('ADMIN_EMAIL valid और ADMIN_PASSWORD 12 से 256 characters का होना चाहिए।'); process.exitCode = 1; return;
  }
  const db = openDatabase();
  try {
    const existing = db.prepare('SELECT id,role FROM users WHERE email = ?').get(email);
    if (existing) {
      if (existing.role === 'admin') { console.error('यह admin email पहले से मौजूद है; कोई बदलाव नहीं किया गया।'); process.exitCode = 1; return; }
      console.error('यह email student account के रूप में मौजूद है; अलग admin email चुनें।'); process.exitCode = 1; return;
    }
    const credentials = hashPassword(password); const userId = id('admin'); const timestamp = now();
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO users (id,name,email,password_hash,password_salt,role,exam,created_at) VALUES (?,?,?,?,?,?,?,?)').run(userId, name.slice(0, 80), email, credentials.hash, credentials.salt, 'admin', 'SSC', timestamp);
      db.prepare('INSERT INTO admins (user_id,permissions,created_at) VALUES (?,?,?)').run(userId, JSON.stringify(['content:write', 'content:publish', 'users:read']), timestamp);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    console.log(`Admin created: ${email}`);
  } finally { closeDatabase(db); }
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
