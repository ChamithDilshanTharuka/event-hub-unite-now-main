import express from 'express';
import bcrypt from 'bcrypt';
import pool from '../db.js';

const router = express.Router();

// Signup
router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.json({ success: false, message: 'All fields are required.' });
  }
  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing.length > 0) {
      return res.json({ success: false, message: 'Username or email already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);
    res.json({ success: true, message: 'Registration successful.' });
  } catch (err) {
    res.json({ success: false, message: 'Database error.' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: 'All fields are required.' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = users[0];
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user_id = user.id;
      req.session.username = user.username;
      res.json({ success: true, message: 'Login successful.' });
    } else {
      res.json({ success: false, message: 'Invalid credentials.' });
    }
  } catch (err) {
    res.json({ success: false, message: 'Database error.' });
  }
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

export default router; 