const { analyzeAudioBuffer } = require('../services/voiceEngine');
const { recordSecurityEvent } = require('../services/blockchainService');
const VoiceAnalysis = require('../models/VoiceAnalysis');
const { inMemoryDB } = require('../config/db');

// @route   POST /api/voice/analyze
const analyzeVoice = async (req, res) => {
  try {
    let buffer = null;
    let fileName = 'audio_sample.wav';
    let mimeType = 'audio/wav';

    if (req.file) {
      buffer = req.file.buffer;
      fileName = req.file.originalname;
      mimeType = req.file.mimetype;
    } else if (req.body.audioBase64) {
      // Direct browser mic recording passed as base64
      const matches = req.body.audioBase64.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
      if (matches && matches.length === 3) {
        mimeType = matches[1];
        buffer = Buffer.from(matches[2], 'base64');
      } else {
        buffer = Buffer.from(req.body.audioBase64, 'base64');
      }
      fileName = req.body.fileName || 'microphone_recording.webm';
    } else {
      return res.status(400).json({ success: false, message: 'Please upload an audio file or record speech via microphone.' });
    }

    // Run acoustic deepfake analysis engine
    const analysis = await analyzeAudioBuffer(buffer, fileName, mimeType);


    // Anchor voice cloning risk analysis to Blockchain
    const blockchainTx = await recordSecurityEvent({
      eventType: 'Voice-Clone Authenticity Analysis',
      indicatorOrFile: fileName,
      riskScore: analysis.riskScore,
      severity: analysis.syntheticVoiceRisk === 'Critical' ? 'Critical' : analysis.syntheticVoiceRisk === 'High' ? 'High' : 'Low',
      details: `${analysis.verdict} | Authenticity: ${analysis.authenticityScore}% | Synthetic Risk: ${analysis.syntheticVoiceRisk}`
    });

    const recordData = {
      fileName: analysis.fileName,
      fileSize: analysis.fileSize,
      format: analysis.format,
      authenticityScore: analysis.authenticityScore,
      syntheticVoiceRisk: analysis.syntheticVoiceRisk,
      confidenceScore: analysis.confidenceScore,
      riskScore: analysis.riskScore,
      detectedAnomalies: analysis.detectedAnomalies,
      metrics: analysis.metrics,
      verdict: analysis.verdict,
      recommendation: analysis.recommendation,
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

    // Store in DB or in-memory
    try {
      const saved = await VoiceAnalysis.create(recordData);
      recordData._id = saved._id;
    } catch (e) {
      recordData._id = 'voice_' + Date.now();
      inMemoryDB.voiceAnalyses.unshift(recordData);
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

// @route   GET /api/voice/history
const getVoiceHistory = async (req, res) => {
  try {
    let records = [];
    try {
      records = await VoiceAnalysis.find().sort({ createdAt: -1 }).limit(20);
    } catch (e) {
      // Mongo fallback
    }

    if (!records || records.length === 0) {
      records = inMemoryDB.voiceAnalyses || [];
    }

    res.json({ success: true, data: records });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  analyzeVoice,
  getVoiceHistory
};

