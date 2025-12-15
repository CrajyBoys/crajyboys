require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { init, run, get, all } = require('./db');

// --------------------
// App setup
// --------------------
const app = express();
app.use(express.json());
app.use(cors());

// Initialize DB
init();

// --------------------
// Config
// --------------------
const PORT = process.env.PORT || 4000;
const BASE_URL = 'https://crajy-boys.onrender.com';

// --------------------
// Health check (Render)
// --------------------
app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});

// --------------------
// Email transporter
// --------------------
async function createTransporter() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  } else {
    const testAccount = await nodemailer.createTestAccount();
    console.warn('SMTP not configured — using Ethereal test account');

    return nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass
      }
    });
  }
}

const transporterPromise = createTransporter();

// --------------------
// Helpers
// --------------------
function genTokenAndHash() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}

// --------------------
// Routes
// --------------------

// Register init
app.post('/register-init', async (req, res) => {
  try {
    const { name, email, dob } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'name and email required' });
    }

    const e = email.toLowerCase().trim();
    const { token, tokenHash } = genTokenAndHash();
    const tokenExpiry = Date.now() + 1000 * 60 * 60;
    const now = Math.floor(Date.now() / 1000);

    const existing = await get('SELECT * FROM users WHERE email = ?', [e]);

    if (!existing) {
      await run(
        'INSERT INTO users (name, email, dob, token_hash, token_expiry, verified, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
        [name, e, dob || null, tokenHash, tokenExpiry, now]
      );
    } else {
      await run(
        'UPDATE users SET name = ?, dob = ?, token_hash = ?, token_expiry = ?, verified = 0 WHERE email = ?',
        [name, dob || existing.dob, tokenHash, tokenExpiry, e]
      );
    }

    const transporter = await transporterPromise;
    const verifyUrl = `${BASE_URL}/verify?token=${token}&email=${encodeURIComponent(e)}`;

    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'no-reply@crajy-boys.local',
      to: e,
      subject: 'Verify your email — Crajy Boys',
      text: `Hello ${name},\n\nVerify your email:\n${verifyUrl}\n\nThis link expires in 1 hour.`,
      html: `<p>Hello ${name},</p><p><a href="${verifyUrl}">Verify your email</a></p><p>Link expires in 1 hour.</p>`
    });

    const preview = nodemailer.getTestMessageUrl(info) || null;
    res.json({ ok: true, preview });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Verify email
app.get('/verify', async (req, res) => {
  try {
    const { token, email } = req.query;
    if (!token || !email) return res.status(400).send('Invalid request');

    const e = email.toLowerCase().trim();
    const user = await get('SELECT * FROM users WHERE email = ?', [e]);
    if (!user) return res.status(400).send('Invalid token or email');

    if (Date.now() > Number(user.token_expiry)) {
      return res.status(400).send('Token expired');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    if (tokenHash !== user.token_hash) {
      return res.status(400).send('Invalid token');
    }

    await run(
      'UPDATE users SET verified = 1, token_hash = NULL, token_expiry = NULL WHERE email = ?',
      [e]
    );

    res.send('Email verified successfully. You can now complete registration.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Complete registration
app.post('/complete-registration', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const e = email.toLowerCase().trim();
    const user = await get('SELECT * FROM users WHERE email = ?', [e]);

    if (!user) return res.status(400).json({ error: 'No such user' });
    if (!user.verified) return res.status(400).json({ error: 'Email not verified' });

    const rounds = Number(process.env.BCRYPT_ROUNDS || 12);
    const hash = await bcrypt.hash(password, rounds);

    await run('UPDATE users SET password_hash = ? WHERE email = ?', [hash, e]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Members list
app.get('/members', async (req, res) => {
  try {
    const rows = await all(
      'SELECT name, email, dob, created_at FROM users WHERE verified = 1 ORDER BY created_at DESC'
    );
    res.json({ members: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// --------------------
// Start server (ONCE)
// --------------------
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌍 BASE_URL: ${BASE_URL}`);
});
