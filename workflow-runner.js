require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(express.static('public'));

app.use('/attached_assets', express.static(path.join(__dirname, 'attached_assets')));

const cors=require('cors')
app.use(cors({
  origin: 'https://stage.saintcrownafd1.org', // <-- match exactly where your frontend runs
  credentials: true
}));

app.use(cookieParser());


app.use((req, res, next) => {
  console.log('Hostname:', req.hostname, 'Path:', req.path);
  next();
});


const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});



function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, hashedPassword, salt) {
  const hash = hashPassword(password, salt);
  return hash === hashedPassword;
}

function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Registration
app.post('/api/afd1/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, error: 'Username, email, and password are required' });
  }

  try {
    const existing = await pool.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [username, email]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'User already exists' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hashed = hashPassword(password, salt);

    const insertUser = await pool.query(
        'INSERT INTO users (username, email, password, salt, role, authorized, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id, username, email, role',
        [username, email, hashed, salt, 'user', true]
    );

    const user = insertUser.rows[0];

    // Create JWT Token
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }); // token valid for 7 days

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // only works on HTTPS (disable if testing on localhost)
      sameSite: 'None',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      token,
      message: 'Login successful'
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});



// Middleware to protect admin routes
const authenticateAdminToken = (req, res, next) => {
  const token = req.cookies.admin_token;
  if (!token) {
    return res.redirect('/afd1-login');
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, admin) => {
    if (err) return res.sendStatus(403);
    req.admin = admin;
    next();
  });
};


const adminUsers = [
  { username: 'maxim', password: 'maxim' },
  { username: 'jeffre', password: 'jeffre' }
];


app.post('/api/afd1/admin-login', (req, res) => {
  const { username, password } = req.body;

  // Find user in array
  const admin = adminUsers.find(user => user.username === username && user.password === password);

  if (!admin) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  // Create JWT token
  const token = jwt.sign({
    username: admin.username,
    role: 'admin'
  }, process.env.JWT_SECRET, { expiresIn: '1h' });

  // Set token in HTTP-only cookie
  res.cookie('admin_token', token, {
    httpOnly: true,
    secure: false, // set true in production with HTTPS
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000  // 1 hour
  });

  res.json({ success: true, message: 'Login successful' });
});


// Login
app.post('/api/afd1/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password are required' });
  }

  try {
    const result = await pool.query(
        'SELECT id, username, email, password, salt, role FROM users WHERE username = $1 OR email = $1',
        [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    if (!verifyPassword(password, user.password, user.salt)) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Create JWT Token
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '20m' }); // token valid for 7 days

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // only works on HTTPS (disable if testing on localhost)
      sameSite: 'None',
      maxAge: 20 * 60 * 1000 // 20 mins
    });

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      token,
      message: 'Login successful'
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.get('/api/afd1/check-auth', (req, res) => {
  // console.log('Cookies:', req.cookies);
  const token = req.cookies.token;
  if (!token) return res.json({ authenticated: false });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.json({ authenticated: false });
    res.json({ authenticated: true, user });
  });
});

app.get('/api/afd1/admin-check-auth', (req, res) => {
  const token = req.cookies.admin_token;
  if (!token) return res.json({ authenticated: false });

  jwt.verify(token, process.env.JWT_SECRET, (err, admin) => {
    if (err) return res.json({ authenticated: false });
    res.json({ authenticated: true, admin });
  });
});


app.post('/api/afd1/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  res.json({ success: true, message: 'Logged out successfully' });
});

const https = require('https');


// IMPORTANT
app.get('/swap-quote', async (req, res) => {
  const { sellAmount, taker, buyToken, sellToken } = req.query;

  if (!sellAmount || !taker || !buyToken || !sellToken) {
    return res.status(400).json({ error: "Missing required query parameters" });
  }

  const url = new URL('https://api.0x.org/swap/permit2/quote');
  url.searchParams.append('sellAmount', sellAmount);
  url.searchParams.append('taker', taker);
  url.searchParams.append('buyToken', buyToken);
  url.searchParams.append('sellToken', sellToken);
  url.searchParams.append('chainId', '1');

  try {
    const response = await fetch(url, {
      headers: {
        '0x-api-key': '65c7457f-d011-401b-8def-eb6e902dbc83',
        '0x-version': 'v2',
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("0x API Error:", data);
      return res.status(response.status).json({ error: data.reason || 'Quote failed' });
    }

    res.json(data);
  } catch (e) {
    console.error('Backend swap error:', e);
    res.status(500).json({ error: 'Swap quote fetch failed' });
  }
});



app.get('*', (req, res) => {
  const hostname = req.hostname;
  const requestedPath = req.path === '/' ? '/' : req.path;
  const filename = requestedPath.substring(1) + '.html';
  res.sendFile(path.join(__dirname, 'public', filename));
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Saint Crown Industrial Banking Dashboard running on port ${port}`);
});
