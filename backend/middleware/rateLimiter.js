const rateLimit = require('express-rate-limit');

// General API rate limiter: 120 requests per minute
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Rate limit exceeded. CyberShield DDoS and brute-force mitigation active. Please retry shortly.'
  }
});

// Stricter rate limiter for threat scanning & voice analysis: 60 requests per minute
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Scan engine rate limit reached. Please wait before submitting more threat vectors.'
  }
});

module.exports = { apiLimiter, scanLimiter };
