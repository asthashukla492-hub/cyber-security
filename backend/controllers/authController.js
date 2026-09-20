const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { inMemoryDB } = require('../config/db');
const { JWT_SECRET } = require('../middleware/auth');

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
};

// @route   POST /api/auth/register
const register = async (req, res) => {
  try {
    const { name, email, password, role, organization } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide name, email, and password' });
    }

    // Try MongoDB
    try {
      const userExists = await User.findOne({ email: email.toLowerCase() });
      if (userExists) {
        return res.status(400).json({ success: false, message: 'User already exists with this email' });
      }

      const user = await User.create({
        name,
        email: email.toLowerCase(),
        password,
        role: role || 'analyst',
        organization: organization || 'CyberShield Security Ops'
      });

      return res.status(201).json({
        success: true,
        token: generateToken(user),
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          organization: user.organization
        }
      });
    } catch (dbErr) {
      // Fallback in-memory
      const existing = inMemoryDB.users.find(u => u.email === email.toLowerCase());
      if (existing) {
        return res.status(400).json({ success: false, message: 'User already exists with this email' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = {
        _id: 'user_' + Date.now(),
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
        role: role || 'analyst',
        organization: organization || 'CyberShield Security Ops',
        createdAt: new Date()
      };

      inMemoryDB.users.push(newUser);

      return res.status(201).json({
        success: true,
        token: generateToken(newUser),
        user: {
          id: newUser._id,
          name: newUser.name,
          email: newUser.email,
          role: newUser.role,
          organization: newUser.organization
        }
      });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   POST /api/auth/login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }

    let user = null;
    try {
      user = await User.findOne({ email: email.toLowerCase() });
    } catch (e) {
      // Mongo not available
    }

    if (!user) {
      user = inMemoryDB.users.find(u => u.email === email.toLowerCase());
    }

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or credentials' });
    }

    const isMatch = typeof user.matchPassword === 'function'
      ? await user.matchPassword(password)
      : await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or credentials' });
    }

    res.json({
      success: true,
      token: generateToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        organization: user.organization
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   POST /api/auth/demo
// Instant 1-click access for evaluation without registration friction
const demoLogin = async (req, res) => {
  const demoUser = {
    _id: 'demo_analyst_01',
    name: 'Lead Threat Analyst',
    email: 'analyst@cybershield.io',
    role: 'admin',
    organization: 'Global Cyber Defense Center'
  };

  res.json({
    success: true,
    token: generateToken(demoUser),
    user: demoUser
  });
};

// @route   GET /api/auth/me
const getMe = async (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
};

module.exports = {
  register,
  login,
  demoLogin,
  getMe
};
