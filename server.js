const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'linx_secret_2025';

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/linx')
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
  photo:    { type: String, default: null },
  profileTheme: { type: String, default: 'default' },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  profileViews: { type: Number, default: 0 },
  links:    [LinkSchema],
  reviews:  [{
    name:    { type: String, required: true },
    message: { type: String, required: true },
    rating:  { type: Number, default: 5 },
    time:    { type: String },
  }],
  notifications: [{
    id:        { type: String },
    type:      { type: String },
    linkTitle: { type: String },
    linkIcon:  { type: String },
    time:      { type: String },
    read:      { type: Boolean, default: false },
  }],
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// ── FOUNDER PHOTOS SCHEMA ─────────────────────────────────
const FounderPhotoSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  photo: { type: String, default: null },
});
const FounderPhoto = mongoose.model('FounderPhoto', FounderPhotoSchema);

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


app.get('/', (req, res) => res.json({ message: 'API is running!' }));

// ── GOOGLE AUTH ───────────────────────────────────────────
app.post('/api/google-auth', async (req, res) => {
  try {
    const { credential, password, username } = req.body;
    if (!credential) return res.status(400).json({ message: 'Google credential required' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { email, email_verified } = ticket.getPayload();

    if (!email_verified) return res.status(400).json({ message: 'Google email not verified' });

    const existing = await User.findOne({ email });

    if (existing) {
      const token = jwt.sign({ id: existing._id, role: existing.role }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: { id: existing._id.toString(), username: existing.username, email: existing.email, role: existing.role, bio: existing.bio, avatar: existing.avatar } });
    }

    if (!password || !username) return res.status(202).json({ message: 'new_user', email });

    if (password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters' });
    if (await User.findOne({ username })) return res.status(409).json({ message: 'Username already taken' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await new User({ username, email, password: hashed }).save();
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, role: user.role, bio: user.bio, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ message: 'Google auth failed', error: err.message });
  }
});

// ── AUTH ROUTES ───────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email/username and password required' });

    const user = await User.findOne({ $or: [{ email }, { username: email }] });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!await bcrypt.compare(password, user.password))
      return res.status(401).json({ message: 'Wrong password' });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id.toString(), username: user.username, email: user.email, role: user.role, bio: user.bio, avatar: user.avatar } });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ── USER PROFILE ──────────────────────────────────────────
app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password -notifications -links');
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ ...user.toObject(), id: user._id, profileViews: user.profileViews || 0 });
});

app.patch('/api/me', auth, async (req, res) => {
  try {
    const { bio, avatar, photo, profileTheme } = req.body;
    const updateData = { bio, avatar, profileTheme };
    // Only update photo if provided
    if (photo !== undefined) updateData.photo = photo;
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updateData },
      { new: true }
    ).select('-password -notifications');
    res.json({ ...user.toObject(), id: user._id });
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

// track click (authenticated)
app.post('/api/links/:linkId/click', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const link = user.links.id(req.params.linkId);
    if (link) {
      link.clicks += 1;
      user.notifications.unshift({ id: Date.now().toString(), type: 'click', linkTitle: link.title, linkIcon: link.icon, time: new Date().toISOString(), read: false });
      if (user.notifications.length > 50) user.notifications = user.notifications.slice(0, 50);
      await user.save();
    }
    res.json({ clicks: link?.clicks });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── NOTIFICATIONS ROUTES ──────────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('notifications');
    res.json(user.notifications || []);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.patch('/api/notifications/read', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.notifications.forEach(n => { n.read = true; });
    await user.save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.delete('/api/notifications', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.notifications = [];
    await user.save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── FOUNDER PHOTOS ROUTES ─────────────────────────────────
app.get('/api/founder-photos', async (req, res) => {
  try {
    const photos = await FounderPhoto.find();
    const result = {};
    photos.forEach(p => { result[p.name] = p.photo; });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/founder-photos', auth, adminOnly, async (req, res) => {
  try {
    const { name, photo } = req.body;
    await FounderPhoto.findOneAndUpdate({ name }, { photo }, { upsert: true, new: true });
    const photos = await FounderPhoto.find();
    const result = {};
    photos.forEach(p => { result[p.name] = p.photo; });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── PUBLIC ROUTES ────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({ role: 'user' }).select('-password');
    res.json(users.map(u => ({
      id: u._id, username: u.username, bio: u.bio, avatar: u.avatar, photo: u.photo || null,
      linkCount: u.links.filter(l => l.active).length,
      totalClicks: u.links.reduce((s, l) => s + (l.clicks || 0), 0),
      createdAt: u.createdAt
    })));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $inc: { profileViews: 1 } },
      { new: true }
    ).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      id: user._id, username: user.username, bio: user.bio, avatar: user.avatar, photo: user.photo || null,
      profileTheme: user.profileTheme || 'default',
      profileViews: user.profileViews || 0,
      links: user.links.filter(l => l.active).sort((a, b) => a.order - b.order)
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── REVIEWS ROUTES ─────────────────────────────────────────
app.get('/api/users/:id/reviews', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('reviews');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user.reviews || []);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/users/:id/reviews', async (req, res) => {
  try {
    const { name, message, rating } = req.body;
    if (!name?.trim() || !message?.trim()) return res.status(400).json({ message: 'Name and message required' });
    if (rating < 1 || rating > 5) return res.status(400).json({ message: 'Rating must be 1-5' });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.reviews.unshift({ name: name.trim(), message: message.trim(), rating: rating || 5, time: new Date().toISOString() });
    user.notifications.unshift({ id: Date.now().toString(), type: 'review', linkTitle: `${name.trim()} left you a ${rating}⭐ review: "${message.trim().slice(0, 60)}${message.length > 60 ? '...' : ''}"`, linkIcon: '💬', time: new Date().toISOString(), read: false });
    if (user.notifications.length > 50) user.notifications = user.notifications.slice(0, 50);
    await user.save();
    res.json(user.reviews);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/users/:userId/links/:linkId/click', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const link = user.links.id(req.params.linkId);
    if (link) {
      link.clicks += 1;
      user.notifications.unshift({ id: Date.now().toString(), type: 'click', linkTitle: link.title, linkIcon: link.icon, time: new Date().toISOString(), read: false });
      if (user.notifications.length > 50) user.notifications = user.notifications.slice(0, 50);
      await user.save();
    }
    res.json({ clicks: link?.clicks });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── ADMIN ROUTES ──────────────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const users = await User.find({ role: 'user' }).select('-password');
  res.json(users);
});

app.post('/api/admin/broadcast', auth, adminOnly, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ message: 'Message is required' });
    const notif = { id: Date.now().toString(), type: 'announcement', linkTitle: message.trim(), linkIcon: '📢', time: new Date().toISOString(), read: false };
    await User.updateMany({ role: 'user' }, { $push: { notifications: { $each: [notif], $position: 0 } } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
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

app.listen(5000, () => {
  console.log('Server running on port 5000');
  // Keep Render free tier alive by self-pinging every 14 minutes
  setInterval(() => {
    fetch('https://linxbackend.onrender.com/').catch(() => {});
  }, 14 * 60 * 1000);
});
