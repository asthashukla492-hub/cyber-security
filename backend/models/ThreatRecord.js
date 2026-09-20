const mongoose = require('mongoose');

const threatRecordSchema = new mongoose.Schema({
  indicator: {
    type: String,
    required: true,
    index: true
  },
  indicatorType: {
    type: String,
    enum: ['url', 'ip', 'domain', 'hash', 'text'],
    required: true
  },
  threatScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  threatCategory: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['Clean', 'Low', 'Medium', 'High', 'Critical'],
    required: true
  },
  explanation: {
    type: String,
    required: true
  },
  recommendedAction: {
    type: String,
    required: true
  },
  indicators: {
    type: Array,
    default: []
  },
  metadata: {
    type: Object,
    default: {}
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

module.exports = mongoose.model('ThreatRecord', threatRecordSchema);
