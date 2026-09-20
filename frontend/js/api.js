/**
 * CyberShield API Client
 * Enterprise Cybersecurity & Voice-Cloning Defense Gateway
 */

const API_BASE = window.location.origin.includes(':5000') 
  ? '/api' 
  : 'http://localhost:5000/api';

const CyberAPI = {
  // Check backend server health and status
  async checkHealth() {
    try {
      const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('[CyberAPI] Health check unreachable:', err.message);
      return {
        status: 'OFFLINE',
        service: 'CyberShield Offline Standby',
        blockchain: { network: 'Ethereum Sepolia Testnet (Cached)', status: 'Standby' }
      };
    }
  },

  // Scan indicator (URL, IP, Domain, Hash, or Text)
  async scanThreat(indicator) {
    try {
      const res = await fetch(`${API_BASE}/threats/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Scan failed');
      return data;
    } catch (err) {
      console.error('[CyberAPI] Threat scan failed:', err);
      throw err;
    }
  },

  // Retrieve recent threat scan audit history
  async getThreatHistory() {
    try {
      const res = await fetch(`${API_BASE}/threats/history`);
      const data = await res.json();
      return data.success ? data.data : [];
    } catch (err) {
      console.warn('[CyberAPI] Threat history fetch error:', err);
      return [];
    }
  },

  // Analyze voice sample via base64 or FormData
  async analyzeVoice({ audioBase64, audioBlob, fileName = 'recording.wav' }) {
    try {
      let res;
      if (audioBlob) {
        const formData = new FormData();
        formData.append('audio', audioBlob, fileName);
        res = await fetch(`${API_BASE}/voice/analyze`, {
          method: 'POST',
          body: formData
        });
      } else {
        res = await fetch(`${API_BASE}/voice/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            audioBase64: audioBase64 || null,
            fileName: fileName
          })
        });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Voice analysis failed');
      return data;
    } catch (err) {
      console.error('[CyberAPI] Voice analysis error:', err);
      throw err;
    }
  },

  // Retrieve voice analysis audit history
  async getVoiceHistory() {
    try {
      const res = await fetch(`${API_BASE}/voice/history`);
      const data = await res.json();
      return data.success ? data.data : [];
    } catch (err) {
      console.warn('[CyberAPI] Voice history fetch error:', err);
      return [];
    }
  },

  // Intelligence stats
  async getIntelligenceStats() {
    try {
      const res = await fetch(`${API_BASE}/intelligence/stats`);
      const data = await res.json();
      return data.success ? data.data : null;
    } catch (err) {
      console.warn('[CyberAPI] Intel stats fetch error:', err);
      return null;
    }
  },

  // Global Threat Feed
  async getIntelligenceFeed() {
    try {
      const res = await fetch(`${API_BASE}/intelligence/feed`);
      const data = await res.json();
      return data.success ? data.data : [];
    } catch (err) {
      console.warn('[CyberAPI] Intel feed error:', err);
      return [];
    }
  },

  // MITRE ATT&CK tactical matrix
  async getMitreMatrix() {
    try {
      const res = await fetch(`${API_BASE}/intelligence/mitre`);
      const data = await res.json();
      return data.success ? data.data : [];
    } catch (err) {
      console.warn('[CyberAPI] MITRE matrix error:', err);
      return [];
    }
  },

  // Blockchain ledger stats
  async getBlockchainStats() {
    try {
      const res = await fetch(`${API_BASE}/blockchain/stats`);
      const data = await res.json();
      return data.success ? data.data : null;
    } catch (err) {
      console.warn('[CyberAPI] Blockchain stats error:', err);
      return null;
    }
  },

  // Blockchain Ledger entries
  async getBlockchainLedger() {
    try {
      const res = await fetch(`${API_BASE}/blockchain/ledger`);
      const data = await res.json();
      return data.success ? data.data : [];
    } catch (err) {
      console.warn('[CyberAPI] Blockchain ledger error:', err);
      return [];
    }
  },

  // Verify transaction on blockchain
  async verifyTransaction(txHash) {
    try {
      const res = await fetch(`${API_BASE}/blockchain/verify/${encodeURIComponent(txHash)}`);
      const data = await res.json();
      return data;
    } catch (err) {
      console.error('[CyberAPI] Transaction verification error:', err);
      throw err;
    }
  }
};

window.CyberAPI = CyberAPI;
