const express = require('express');
const router = express.Router();
const {
  getDashboardOverview,
  getIntelligenceStats,
  getIntelligenceFeed,
  getMitreMatrix
} = require('../controllers/intelligenceController');

router.get('/overview', getDashboardOverview);
router.get('/stats', getIntelligenceStats);
router.get('/feed', getIntelligenceFeed);
router.get('/mitre', getMitreMatrix);

module.exports = router;
