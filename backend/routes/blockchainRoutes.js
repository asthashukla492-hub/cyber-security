const express = require('express');
const router = express.Router();
const { getLedger, verifyRecord, getBlockchainStats } = require('../controllers/blockchainController');

router.get('/stats', getBlockchainStats);
router.get('/ledger', getLedger);
router.get('/verify/:hash', verifyRecord);

module.exports = router;
