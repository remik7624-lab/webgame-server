const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'webgame_secret_key_2024';

// Database setup (lowdb - JSON file, no compilation needed)
const adapter = new FileSync('db.json');
const db = low(adapter);

db.defaults({
  users: [],
  games: [],
  messages: []
}).write();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ===== AUTH =====
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (username.length < 3) return res.status(400).json({ error: 'Username too short' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    const exists = db.get('users').find({ username }).value();
    if (exists) return res.status(400).json({ error: 'Username taken' });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      username,
      password: hash,
      avatar: '',
      bio: '',
      friends: [],
      createdAt: new Date().toISOString()
    };
    db.get('users').push(user).write();

    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username, id: user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = db.get('users').find({ username }).value();
    if (!user) return res.status(400).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong password' });

    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username, id: user.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== GAMES =====
app.get('/api/games', (req, res) => {
  const games = db.get('games').value();
  res.json(games);
});

app.post('/api/games', authMiddleware, (req, res) => {
  try {
    const { title, url, category, description, thumbnail } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'Missing fields' });

    const game = {
      id: uuidv4(),
      title,
      url,
      category: category || 'Другое',
      description: description || '',
      thumbnail: thumbnail || '',
      addedBy: req.user.username,
      likes: 0,
      plays: 0,
      createdAt: new Date().toISOString()
    };
    db.get('games').push(game).write();
    res.json(game);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/games/:id/play', (req, res) => {
  const game = db.get('games').find({ id: req.params.id });
  if (!game.value()) return res.status(404).json({ error: 'Not found' });
  game.assign({ plays: (game.value().plays || 0) + 1 }).write();
  res.json({ ok: true });
});

app.post('/api/games/:id/like', authMiddleware, (req, res) => {
  const game = db.get('games').find({ id: req.params.id });
  if (!game.value()) return res.status(404).json({ error: 'Not found' });
  game.assign({ likes: (game.value().likes || 0) + 1 }).write();
  res.json({ likes: game.value().likes });
});

// ===== CHAT =====
app.get('/api/messages', authMiddleware, (req, res) => {
  const messages = db.get('messages').takeRight(50).value();
  res.json(messages);
});

app.post('/api/messages', authMiddleware, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Empty message' });
  const msg = {
    id: uuidv4(),
    username: req.user.username,
    text,
    createdAt: new Date().toISOString()
  };
  db.get('messages').push(msg).write();
  res.json(msg);
});

// ===== HEALTH =====
app.get('/', (req, res) => {
  res.json({ status: 'WEB_GAME Server running!', version: '3.0' });
});

app.listen(PORT, () => {
  console.log(`✅ WEB_GAME Server running on port ${PORT}`);
});
