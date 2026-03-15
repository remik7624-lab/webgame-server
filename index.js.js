const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'webgame_secret_2026';

// ── DIRS ──────────────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const GAMES_DIR = path.join(UPLOADS_DIR, 'games');
const ICONS_DIR = path.join(UPLOADS_DIR, 'icons');
const AVATARS_DIR = path.join(UPLOADS_DIR, 'avatars');
[UPLOADS_DIR, GAMES_DIR, ICONS_DIR, AVATARS_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'webgame.db'));

// Promisify helpers
const run = (sql, params=[]) => new Promise((res,rej) => db.run(sql, params, function(err){ err ? rej(err) : res(this); }));
const get = (sql, params=[]) => new Promise((res,rej) => db.get(sql, params, (err,row) => err ? rej(err) : res(row)));
const all = (sql, params=[]) => new Promise((res,rej) => db.all(sql, params, (err,rows) => err ? rej(err) : res(rows)));

// Init tables
db.serialize(() => {
  db.run('PRAGMA journal_mode=WAL');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    avatar TEXT, bio TEXT DEFAULT '', created_at INTEGER DEFAULT (strftime('%s','now')),
    last_seen INTEGER DEFAULT (strftime('%s','now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS games (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT DEFAULT '',
    category TEXT DEFAULT 'arcade', author_id TEXT NOT NULL,
    file_path TEXT, icon_path TEXT, plays INTEGER DEFAULT 0, likes INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')), updated_at INTEGER DEFAULT (strftime('%s','now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS play_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, game_id TEXT NOT NULL,
    played_at INTEGER DEFAULT (strftime('%s','now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS favorites (
    user_id TEXT NOT NULL, game_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')), PRIMARY KEY(user_id,game_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS friends (
    user_id TEXT NOT NULL, friend_id TEXT NOT NULL, status TEXT DEFAULT 'pending',
    created_at INTEGER DEFAULT (strftime('%s','now')), PRIMARY KEY(user_id,friend_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, from_id TEXT NOT NULL, to_id TEXT NOT NULL,
    content TEXT NOT NULL, color TEXT DEFAULT '#7c5cfc', read INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')))`);
  db.run(`CREATE TABLE IF NOT EXISTS game_likes (
    user_id TEXT NOT NULL, game_id TEXT NOT NULL, PRIMARY KEY(user_id,game_id))`);
  console.log('✅ Database ready');
});

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 60000, max: 200 }));
app.use('/uploads', express.static(UPLOADS_DIR));

// ── MULTER ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, file.fieldname === 'icon' ? ICONS_DIR : file.fieldname === 'avatar' ? AVATARS_DIR : GAMES_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 50*1024*1024 } });

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    db.run("UPDATE users SET last_seen=strftime('%s','now') WHERE id=?", [req.user.id]);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

const sanitize = s => typeof s === 'string' ? s.replace(/<[^>]+>/g,'').trim().substring(0,1000) : '';

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполни все поля' });
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Ник 3-20 символов' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    if (!/^[a-zA-Z0-9_а-яА-ЯёЁ]+$/.test(username)) return res.status(400).json({ error: 'Недопустимые символы в нике' });
    const existing = await get('SELECT id FROM users WHERE username=?', [username]);
    if (existing) return res.status(409).json({ error: 'Ник занят' });
    const hash = await bcrypt.hash(password, 12);
    const id = uuidv4();
    await run('INSERT INTO users (id,username,password_hash) VALUES (?,?,?)', [id, username, hash]);
    const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, username, avatar: null, bio: '' } });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await get('SELECT * FROM users WHERE username=?', [username]);
    if (!user) return res.status(401).json({ error: 'Неверный ник или пароль' });
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Неверный ник или пароль' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar, bio: user.bio } });
  } catch(e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users/me', auth, async (req, res) => {
  const user = await get('SELECT id,username,avatar,bio,created_at FROM users WHERE id=?', [req.user.id]);
  const { c: gamesCount } = await get('SELECT COUNT(*) c FROM games WHERE author_id=?', [req.user.id]);
  const { c: playsTotal } = await get('SELECT COUNT(*) c FROM play_history WHERE user_id=?', [req.user.id]);
  res.json({ ...user, gamesCount, playsTotal });
});

app.patch('/api/users/me', auth, async (req, res) => {
  const { username, bio } = req.body;
  if (username) {
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Ник 3-20 символов' });
    const taken = await get('SELECT id FROM users WHERE username=? AND id!=?', [username, req.user.id]);
    if (taken) return res.status(409).json({ error: 'Ник занят' });
    await run('UPDATE users SET username=? WHERE id=?', [sanitize(username), req.user.id]);
  }
  if (bio !== undefined) await run('UPDATE users SET bio=? WHERE id=?', [sanitize(bio), req.user.id]);
  res.json({ success: true });
});

app.post('/api/users/me/avatar', auth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  const url = `/uploads/avatars/${req.file.filename}`;
  await run('UPDATE users SET avatar=? WHERE id=?', [url, req.user.id]);
  res.json({ avatar: url });
});

app.get('/api/users/search', auth, async (req, res) => {
  const q = req.query.q || '';
  const users = await all('SELECT id,username,avatar FROM users WHERE username LIKE ? AND id!=? LIMIT 20', [`%${q}%`, req.user.id]);
  res.json(users);
});

// ── GAMES ─────────────────────────────────────────────────────────────────────
app.get('/api/games', async (req, res) => {
  const { category='all', search='', sort='new', limit=20, offset=0 } = req.query;
  let q = 'SELECT g.*,u.username author_name FROM games g LEFT JOIN users u ON g.author_id=u.id WHERE 1=1';
  const p = [];
  if (category && category !== 'all') { q += ' AND g.category=?'; p.push(category); }
  if (search) { q += ' AND (g.title LIKE ? OR g.description LIKE ?)'; p.push(`%${search}%`,`%${search}%`); }
  q += sort==='popular' ? ' ORDER BY g.plays DESC' : sort==='likes' ? ' ORDER BY g.likes DESC' : ' ORDER BY g.created_at DESC';
  q += ' LIMIT ? OFFSET ?'; p.push(parseInt(limit), parseInt(offset));
  const games = await all(q, p);
  const { c: total } = await get('SELECT COUNT(*) c FROM games');
  res.json({ games, total });
});

app.post('/api/games', auth, upload.fields([{name:'game',maxCount:1},{name:'icon',maxCount:1}]), async (req, res) => {
  const { title, description='', category='arcade' } = req.body;
  if (!title) return res.status(400).json({ error: 'Название обязательно' });
  const id = uuidv4();
  const filePath = req.files?.game?.[0] ? `/uploads/games/${req.files.game[0].filename}` : null;
  const iconPath = req.files?.icon?.[0] ? `/uploads/icons/${req.files.icon[0].filename}` : null;
  await run('INSERT INTO games (id,title,description,category,author_id,file_path,icon_path) VALUES (?,?,?,?,?,?,?)',
    [id, sanitize(title), sanitize(description), category, req.user.id, filePath, iconPath]);
  res.json({ id, success: true });
});

app.put('/api/games/:id', auth, upload.fields([{name:'game',maxCount:1},{name:'icon',maxCount:1}]), async (req, res) => {
  const game = await get('SELECT * FROM games WHERE id=? AND author_id=?', [req.params.id, req.user.id]);
  if (!game) return res.status(403).json({ error: 'Нет доступа' });
  const { title, description, category } = req.body;
  const sets = []; const p = [];
  if (title) { sets.push('title=?'); p.push(sanitize(title)); }
  if (description!==undefined) { sets.push('description=?'); p.push(sanitize(description)); }
  if (category) { sets.push('category=?'); p.push(category); }
  if (req.files?.game?.[0]) { sets.push('file_path=?'); p.push(`/uploads/games/${req.files.game[0].filename}`); }
  if (req.files?.icon?.[0]) { sets.push('icon_path=?'); p.push(`/uploads/icons/${req.files.icon[0].filename}`); }
  sets.push("updated_at=strftime('%s','now')");
  p.push(req.params.id);
  await run(`UPDATE games SET ${sets.join(',')} WHERE id=?`, p);
  res.json({ success: true });
});

app.delete('/api/games/:id', auth, async (req, res) => {
  const game = await get('SELECT * FROM games WHERE id=? AND author_id=?', [req.params.id, req.user.id]);
  if (!game) return res.status(403).json({ error: 'Нет доступа' });
  await run('DELETE FROM games WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/games/:id/play', auth, async (req, res) => {
  await run('UPDATE games SET plays=plays+1 WHERE id=?', [req.params.id]);
  await run('INSERT INTO play_history (user_id,game_id) VALUES (?,?)', [req.user.id, req.params.id]);
  res.json({ success: true });
});

app.post('/api/games/:id/like', auth, async (req, res) => {
  const ex = await get('SELECT 1 FROM game_likes WHERE user_id=? AND game_id=?', [req.user.id, req.params.id]);
  if (ex) {
    await run('DELETE FROM game_likes WHERE user_id=? AND game_id=?', [req.user.id, req.params.id]);
    await run('UPDATE games SET likes=MAX(0,likes-1) WHERE id=?', [req.params.id]);
    res.json({ liked: false });
  } else {
    await run('INSERT OR IGNORE INTO game_likes (user_id,game_id) VALUES (?,?)', [req.user.id, req.params.id]);
    await run('UPDATE games SET likes=likes+1 WHERE id=?', [req.params.id]);
    res.json({ liked: true });
  }
});

// ── RECOMMENDATIONS ───────────────────────────────────────────────────────────
app.get('/api/recommendations', auth, async (req, res) => {
  const topCats = await all(
    'SELECT g.category,COUNT(*) cnt FROM play_history ph JOIN games g ON ph.game_id=g.id WHERE ph.user_id=? GROUP BY g.category ORDER BY cnt DESC LIMIT 3',
    [req.user.id]);
  let recs = [];
  if (topCats.length > 0) {
    const cats = topCats.map(c=>c.category);
    const ph = `(${cats.map(()=>'?').join(',')})`;
    recs = await all(
      `SELECT g.*,u.username author_name FROM games g LEFT JOIN users u ON g.author_id=u.id
       WHERE g.category IN ${ph} AND g.id NOT IN (SELECT game_id FROM play_history WHERE user_id=? LIMIT 50)
       ORDER BY g.plays DESC LIMIT 8`, [...cats, req.user.id]);
  }
  if (recs.length < 6) {
    const popular = await all('SELECT g.*,u.username author_name FROM games g LEFT JOIN users u ON g.author_id=u.id ORDER BY g.plays DESC LIMIT 10');
    const ids = new Set(recs.map(g=>g.id));
    popular.forEach(g => { if (!ids.has(g.id)) recs.push(g); });
  }
  res.json(recs.slice(0,8));
});

// ── FAVORITES ─────────────────────────────────────────────────────────────────
app.get('/api/favorites', auth, async (req, res) => {
  const favs = await all(
    'SELECT g.*,u.username author_name FROM favorites f JOIN games g ON f.game_id=g.id LEFT JOIN users u ON g.author_id=u.id WHERE f.user_id=? ORDER BY f.created_at DESC',
    [req.user.id]);
  res.json(favs);
});

app.post('/api/favorites/:gameId', auth, async (req, res) => {
  const ex = await get('SELECT 1 FROM favorites WHERE user_id=? AND game_id=?', [req.user.id, req.params.gameId]);
  if (ex) { await run('DELETE FROM favorites WHERE user_id=? AND game_id=?', [req.user.id, req.params.gameId]); res.json({ favorited: false }); }
  else { await run('INSERT OR IGNORE INTO favorites (user_id,game_id) VALUES (?,?)', [req.user.id, req.params.gameId]); res.json({ favorited: true }); }
});

// ── FRIENDS ───────────────────────────────────────────────────────────────────
app.get('/api/friends', auth, async (req, res) => {
  const friends = await all(
    `SELECT u.id,u.username,u.avatar,f.status FROM friends f
     JOIN users u ON CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END=u.id
     WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted'`,
    [req.user.id, req.user.id, req.user.id]);
  const pending = await all(
    `SELECT u.id,u.username,u.avatar FROM friends f JOIN users u ON f.user_id=u.id WHERE f.friend_id=? AND f.status='pending'`,
    [req.user.id]);
  res.json({ friends, pending });
});

app.post('/api/friends/:userId', auth, async (req, res) => {
  if (req.params.userId === req.user.id) return res.status(400).json({ error: 'Нельзя добавить себя' });
  const ex = await get('SELECT 1 FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
    [req.user.id, req.params.userId, req.params.userId, req.user.id]);
  if (ex) return res.status(409).json({ error: 'Уже отправлен запрос' });
  await run("INSERT INTO friends (user_id,friend_id,status) VALUES (?,?,'pending')", [req.user.id, req.params.userId]);
  res.json({ success: true });
});

app.patch('/api/friends/:userId/accept', auth, async (req, res) => {
  await run("UPDATE friends SET status='accepted' WHERE user_id=? AND friend_id=?", [req.params.userId, req.user.id]);
  res.json({ success: true });
});

app.delete('/api/friends/:userId', auth, async (req, res) => {
  await run('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
    [req.user.id, req.params.userId, req.params.userId, req.user.id]);
  res.json({ success: true });
});

// ── MESSAGES ──────────────────────────────────────────────────────────────────
app.get('/api/messages/:userId', auth, async (req, res) => {
  const msgs = await all(
    `SELECT m.*,u.username from_name,u.avatar from_avatar FROM messages m JOIN users u ON m.from_id=u.id
     WHERE (m.from_id=? AND m.to_id=?) OR (m.from_id=? AND m.to_id=?) ORDER BY m.created_at ASC LIMIT 100`,
    [req.user.id, req.params.userId, req.params.userId, req.user.id]);
  await run('UPDATE messages SET read=1 WHERE from_id=? AND to_id=?', [req.params.userId, req.user.id]);
  res.json(msgs);
});

app.post('/api/messages/:userId', auth, async (req, res) => {
  const { content, color='#7c5cfc' } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Пустое сообщение' });
  await run('INSERT INTO messages (from_id,to_id,content,color) VALUES (?,?,?,?)',
    [req.user.id, req.params.userId, sanitize(content), color]);
  res.json({ success: true });
});

// ── STATS & HEALTH ────────────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  const { c: users } = await get('SELECT COUNT(*) c FROM users');
  const { c: games } = await get('SELECT COUNT(*) c FROM games');
  const { c: plays } = await get('SELECT COUNT(*) c FROM play_history');
  res.json({ users, games, plays });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🎮 WEB_GAME Server running on port ${PORT}`));
