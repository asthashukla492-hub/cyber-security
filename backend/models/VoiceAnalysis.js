const mongoose = require('mongoose');

const voiceAnalysisSchema = new mongoose.Schema({
  fileName: {
    type: String,
    required: true
  },
  fileSize: Number,
  duration: Number,
  format: String,
  authenticityScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  syntheticVoiceRisk: {
    type: String,
    enum: ['Low', 'Moderate', 'High', 'Critical'],
    required: true
  },
  confidenceScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  detectedAnomalies: [
    {
      name: String,
      severity: String,
      score: Number,
      description: String
    }
  ],
  metrics: {
    pitchJitterPercent: Number,
    shimmerPercent: Number,
    harmonicToNoiseRatio: Number,
    spectralFlatness: Number,
    neuralVocoderArtifacts: Number,
    phaseDiscontinuity: Number
  },
  verdict: {
    type: String,
    required: true
  },
  recommendation: {
    type: String,
    required: true
  },
  eventHash: {
    type: String,
    required: true,
    unique: true
  },
  blockchainTx: {
    txHash: String,
    blockNumber: Number,
    timestamp: Date,
    status: {
      type: String,
      enum: ['pending', 'confirmed', 'verified_ledger'],
      default: 'verified_ledger'
    },
    contractAddress: String
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('VoiceAnalysis', voiceAnalysisSchema);
