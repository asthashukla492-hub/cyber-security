const { analyzeIndicator } = require('../services/threatEngine');
const { recordSecurityEvent } = require('../services/blockchainService');
const ThreatRecord = require('../models/ThreatRecord');
const { inMemoryDB } = require('../config/db');

// @route   POST /api/threats/scan
const scanIndicator = async (req, res) => {
  try {
    const { indicator } = req.body;

    if (!indicator || typeof indicator !== 'string' || !indicator.trim()) {
      return res.status(400).json({ success: false, message: 'Please provide a valid indicator (URL, IP, Domain, Hash, or Text)' });
    }

    // 1. Run multi-factor threat detection engine
    const analysis = analyzeIndicator(indicator.trim());

    // 2. Automatically anchor threat detection into Blockchain Verification Ledger
    const blockchainTx = await recordSecurityEvent({
      eventType: `Threat Indicator: ${analysis.indicatorType.toUpperCase()}`,
      indicatorOrFile: indicator.trim().substring(0, 80),
      riskScore: analysis.threatScore,
      severity: analysis.severity,
      details: analysis.explanation
    });

    const recordData = {
      indicator: analysis.indicator,
      indicatorType: analysis.indicatorType,
      threatScore: analysis.threatScore,
      threatCategory: analysis.threatCategory,
      severity: analysis.severity,
      explanation: analysis.explanation,
      recommendedAction: analysis.recommendedAction,
      indicators: analysis.indicators,
      metadata: analysis.metadata,
      eventHash: blockchainTx.eventHash,
      blockchainTx: {
        txHash: blockchainTx.txHash,
        blockNumber: blockchainTx.blockNumber,
        timestamp: new Date(blockchainTx.timestamp),
        status: 'confirmed',
        contractAddress: blockchainTx.contractAddress
      },
      user: req.user?._id || null,
      createdAt: new Date()
    };

    // 3. Store in Database
    try {
      const saved = await ThreatRecord.create(recordData);
      recordData._id = saved._id;
    } catch (e) {
      recordData._id = 'threat_' + Date.now();
      inMemoryDB.threatRecords.unshift(recordData);
    }

    res.json({
      success: true,
      data: {
        ...analysis,
        eventHash: blockchainTx.eventHash,
        blockchainTx
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/threats/history
const getThreatHistory = async (req, res) => {
  try {
    let records = [];
    try {
      records = await ThreatRecord.find().sort({ createdAt: -1 }).limit(25);
    } catch (e) {
      // Mongo fallback
    }

    if (!records || records.length === 0) {
      records = inMemoryDB.threatRecords || [];
    }

    res.json({ success: true, data: records });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  scanIndicator,
  getThreatHistory
};

