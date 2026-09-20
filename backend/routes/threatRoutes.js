const express = require('express');
const router = express.Router();
const { scanIndicator, getThreatHistory } = require('../controllers/threatController');
const { optionalAuth } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');

router.post('/scan', scanLimiter, optionalAuth, scanIndicator);
router.get('/history', optionalAuth, getThreatHistory);

module.exports = router;
