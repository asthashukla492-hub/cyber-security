const { getLedgerHistory, verifyHash, getBlockchainStats: getChainStats } = require('../services/blockchainService');

// @route   GET /api/blockchain/stats
const getBlockchainStats = async (req, res) => {
  try {
    const stats = getChainStats();
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/blockchain/ledger
const getLedger = async (req, res) => {
  try {
    const ledger = getLedgerHistory(50);
    res.json({
      success: true,
      count: ledger.length,
      contractAddress: process.env.CONTRACT_ADDRESS || '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
      network: process.env.BLOCKCHAIN_NETWORK || 'Ethereum Sepolia Testnet',
      data: ledger
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/blockchain/verify/:hash
const verifyRecord = async (req, res) => {
  try {
    const { hash } = req.params;
    if (!hash) {
      return res.status(400).json({ success: false, message: 'Hash parameter is required' });
    }

    const verification = verifyHash(hash);
    res.json({
      success: true,
      ...verification,
      ...(verification.record || {}),
      data: verification
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  getBlockchainStats,
  getLedger,
  verifyRecord
};
