const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'linx_secret_2025';

mongoose.connect('mongodb://127.0.0.1:27017/linx')
  .then(() => { console.log('MongoDB connected'); seedAdmin(); })
  .catch(err => console.error('MongoDB error:', err));

// ── SCHEMAS ──────────────────────────────────────────────
const LinkSchema = new mongoose.Schema({
  title: { type: String, required: true },
  url:   { type: String, required: true },
  icon:  { type: String, default: '🔗' },
  clicks:{ type: Number, default: 0 },
  active:{ type: Boolean, default: true },
  order: { type: Number, default: 0 },
}, { timestamps: true });

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  bio:      { type: String, default: '' },
  avatar:   { type: String, default: '🌟' },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  links:    [LinkSchema],
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// ── SEED ADMIN ────────────────────────────────────────────
async function seedAdmin() {
  const exists = await User.findOne({ role: 'admin' });
  if (!exists) {
    const hashed = await bcrypt.hash('admin123', 10);
    await new User({ username: 'admin', email: 'admin@linx.app', password: hashed, role: 'admin' }).save();
    console.log('Admin created → email: admin@linx.app  password: admin123');
  }
}

// ── MIDDLEWARE ────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admins only' });
  next();
}

// ── AUTH ROUTES ───────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ message: 'All fields are required' });

    if (await User.findOne({ email }))
      return res.status(409).json({ message: 'Email already in use' });
    if (await User.findOne({ username }))
      return res.status(409).json({ message: 'Username already taken' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await new User({ username, email, password: hashed }).save();
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, email: user.email, role: user.role, bio: user.bio, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!await bcrypt.compare(password, user.password))
      return res.status(401).json({ message: 'Wrong password' });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, username: user.username, email: user.email, role: user.role, bio: user.bio, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ── USER PROFILE ──────────────────────────────────────────
app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

app.patch('/api/me', auth, async (req, res) => {
  try {
    const { bio, avatar } = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, { bio, avatar }, { new: true }).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── LINKS ROUTES ──────────────────────────────────────────
app.get('/api/links', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('links');
  res.json(user.links.sort((a, b) => a.order - b.order));
});

app.post('/api/links', auth, async (req, res) => {
  try {
    const { title, url, icon } = req.body;
    if (!title || !url) return res.status(400).json({ message: 'Title and URL required' });
    const user = await User.findById(req.user.id);
    const order = user.links.length;
    user.links.push({ title, url, icon: icon || '🔗', order });
    await user.save();
    res.json(user.links.sort((a, b) => a.order - b.order));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/links/:linkId', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const link = user.links.id(req.params.linkId);
    if (!link) return res.status(404).json({ message: 'Link not found' });
    Object.assign(link, req.body);
    await user.save();
    res.json(user.links.sort((a, b) => a.order - b.order));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/links/:linkId', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.links = user.links.filter(l => l._id.toString() !== req.params.linkId);
    await user.save();
    res.json(user.links.sort((a, b) => a.order - b.order));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// track click
app.post('/api/links/:linkId/click', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const link = user.links.id(req.params.linkId);
    if (link) { link.clicks += 1; await user.save(); }
    res.json({ clicks: link?.clicks });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── ADMIN ROUTES ──────────────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find({ role: 'user' }).select('-password');
  res.json(users);
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/users/:id/links/:linkId', auth, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    user.links = user.links.filter(l => l._id.toString() !== req.params.linkId);
    await user.save();
    res.json({ message: 'Link deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── SERVE REACT BUILD ─────────────────────────────────────
const buildPath = path.join(__dirname, '../Frontend/build');
app.use(express.static(buildPath));
app.get('*path', (req, res) => res.sendFile(path.join(buildPath, 'index.html')));

app.listen(5000, () => console.log('Server running on port 5000'));
