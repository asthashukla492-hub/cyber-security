const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const path = require('path');
const { connectDB, getDBStatus } = require('./config/db');
const { apiLimiter } = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middlewares
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: false
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body Parsers with generous limit for audio base64 transmission
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Apply general rate limiter
app.use('/api', apiLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'CyberShield Security Core & Voice-Cloning Protection API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    database: getDBStatus(),
    blockchain: {
      network: process.env.BLOCKCHAIN_NETWORK || 'Ethereum Sepolia Testnet',
      status: 'Synchronized & Ready'
    }
  });
});

// API Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/threats', require('./routes/threatRoutes'));
app.use('/api/voice', require('./routes/voiceRoutes'));
app.use('/api/intelligence', require('./routes/intelligenceRoutes'));
app.use('/api/blockchain', require('./routes/blockchainRoutes'));

// Serve Frontend static assets
app.use(express.static(path.join(__dirname, '../frontend')));

// SPA route fallback for non-API requests
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Centralized error handler
app.use(errorHandler);

// Start server
const startServer = () => {
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🛡️  CyberShield API Server running on port ${PORT}`);
    console.log(`🛡️  Health check: http://localhost:${PORT}/api/health`);
    console.log(`🛡️  Threat Engine: ONLINE`);
    console.log(`🛡️  Voice-Cloning Protection: ONLINE`);
    console.log(`🛡️  Blockchain Verification Ledger: ACTIVE`);
    console.log(`=======================================================`);
  });

  // Attempt database connection in background
  connectDB().catch(err => {
    console.warn('[Database] Background connection caught:', err.message);
  });
};

startServer();

module.exports = app;
