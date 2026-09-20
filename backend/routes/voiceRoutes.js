const express = require('express');
const router = express.Router();
const multer = require('multer');
const { analyzeVoice, getVoiceHistory } = require('../controllers/voiceController');
const { optionalAuth } = require('../middleware/auth');
const { scanLimiter } = require('../middleware/rateLimiter');

// Store audio in memory buffer for real-time acoustic DSP processing
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB max audio
});

router.post('/analyze', scanLimiter, optionalAuth, upload.single('audio'), analyzeVoice);
router.get('/history', optionalAuth, getVoiceHistory);

module.exports = router;
