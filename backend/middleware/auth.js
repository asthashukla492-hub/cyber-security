const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { inMemoryDB } = require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET || 'cybershield-super-secret-key-blockchain-2026';

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);

      // Try database first
      let user = null;
      try {
        user = await User.findById(decoded.id).select('-password');
      } catch (e) {
        // Fallback to in-memory store
      }

      if (!user) {
        user = inMemoryDB.users.find(u => u._id === decoded.id || u.email === decoded.email);
      }

      // If still not found, allow decoded fallback for seamless demo experience
      req.user = user || {
        _id: decoded.id || 'demo-user-id',
        name: decoded.name || 'Security Analyst',
        email: decoded.email || 'analyst@cybershield.io',
        role: decoded.role || 'analyst'
      };

      return next();
    } catch (error) {
      return res.status(401).json({ success: false, message: 'Invalid or expired authorization token' });
    }
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Authorization token required' });
  }
};

const optionalAuth = async (req, res, next) => {
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    return protect(req, res, next);
  }
  req.user = {
    _id: 'guest-analyst',
    name: 'Guest Threat Analyst',
    email: 'guest@cybershield.io',
    role: 'analyst'
  };
  next();
};

module.exports = { protect, optionalAuth, JWT_SECRET };
