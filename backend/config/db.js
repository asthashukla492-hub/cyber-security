const mongoose = require('mongoose');

let isConnected = false;

// In-memory fallback stores if MongoDB is not reachable locally
const inMemoryDB = {
  users: [],
  threatRecords: [],
  voiceAnalyses: []
};

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri || uri.includes('127.0.0.1') || uri.includes('localhost')) {
    // Check if user specifically requested live local mongodb or in-memory mode
    console.log(`[Database] Attempting connection to MongoDB (${uri || 'mongodb://localhost:27017/cybershield'})...`);
  }
  
  try {
    const conn = await mongoose.connect(uri || 'mongodb://127.0.0.1:27017/cybershield', {
      serverSelectionTimeoutMS: 1500,
      connectTimeoutMS: 1500
    });
    isConnected = true;
    console.log(`[Database] MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    isConnected = false;
    console.log(`[Database] Notice: MongoDB not detected locally (${error.message}).`);
    console.log(`[Database] Activating High-Performance Resilient In-Memory Storage Adapter.`);
  }
};

const getDBStatus = () => ({
  connected: isConnected,
  mode: isConnected ? 'MongoDB Live' : 'In-Memory Resilient Mode'
});

module.exports = { connectDB, inMemoryDB, getDBStatus };
