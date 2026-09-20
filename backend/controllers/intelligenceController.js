const ThreatRecord = require('../models/ThreatRecord');
const VoiceAnalysis = require('../models/VoiceAnalysis');
const { inMemoryDB } = require('../config/db');

// @route   GET /api/intelligence/overview
const getDashboardOverview = async (req, res) => {
  try {
    let threatCount = inMemoryDB.threatRecords ? inMemoryDB.threatRecords.length : 0;
    let voiceCount = inMemoryDB.voiceAnalyses ? inMemoryDB.voiceAnalyses.length : 0;
    let criticalCount = (inMemoryDB.threatRecords || []).filter(r => r.severity === 'Critical').length + (inMemoryDB.voiceAnalyses || []).filter(v => v.syntheticVoiceRisk === 'Critical').length;
    let highCount = (inMemoryDB.threatRecords || []).filter(r => r.severity === 'High').length + (inMemoryDB.voiceAnalyses || []).filter(v => v.syntheticVoiceRisk === 'High').length;

    try {
      const dbThreats = await ThreatRecord.countDocuments();
      const dbVoices = await VoiceAnalysis.countDocuments();
      threatCount = Math.max(threatCount, dbThreats);
      voiceCount = Math.max(voiceCount, dbVoices);
      criticalCount += await ThreatRecord.countDocuments({ severity: 'Critical' });
      highCount += await ThreatRecord.countDocuments({ severity: 'High' });
    } catch (e) {
      // In-Memory mode
    }

    // Dynamic risk index calculation
    const totalIncidents = threatCount + voiceCount;
    const computedRisk = totalIncidents === 0 ? 0 : Math.min(94, (criticalCount * 25) + (highCount * 12) + (totalIncidents * 2));

    let threatLevel = 'Clean';
    if (computedRisk >= 80) threatLevel = 'Critical';
    else if (computedRisk >= 60) threatLevel = 'Severe';
    else if (computedRisk >= 40) threatLevel = 'Elevated';
    else if (computedRisk >= 20) threatLevel = 'Moderate';
    else if (computedRisk > 0) threatLevel = 'Low';

    const ipDomainIndicators = (inMemoryDB.threatRecords || []).slice(0, 6).map(r => ({
      indicator: r.indicator,
      type: r.indicatorType ? r.indicatorType.toUpperCase() : 'IOC',
      risk: r.severity || 'Medium',
      score: r.threatScore || 50,
      source: r.threatCategory || 'Threat Detector'
    }));

    const recommendations = [
      {
        id: 'rec-1',
        title: 'Mandate Multi-Factor Verification for Critical Transactions',
        priority: 'High',
        category: 'Biometric & Auth',
        description: 'Verify all incoming voice or financial authorization requests via secondary authenticated channels.'
      },
      {
        id: 'rec-2',
        title: 'Real-Time Blockchain Audit Verification',
        priority: 'Medium',
        category: 'Compliance & Audit',
        description: 'Ensure all threat scans and biometric checks are anchored to the Sepolia ledger for tamper-proof compliance.'
      }
    ];

    res.json({
      success: true,
      data: {
        overallRiskScore: computedRisk,
        threatLevel,
        threatStats: {
          totalThreatsScanned: threatCount,
          criticalThreats: criticalCount,
          voiceClonesBlocked: voiceCount,
          blockchainRecordsAnchored: threatCount + voiceCount
        },
        ipDomainIndicators,
        riskTrend: [],
        recommendations
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/intelligence/stats
const getIntelligenceStats = async (req, res) => {
  try {
    let threatCount = inMemoryDB.threatRecords ? inMemoryDB.threatRecords.length : 0;
    let voiceCount = inMemoryDB.voiceAnalyses ? inMemoryDB.voiceAnalyses.length : 0;
    let criticalCount = (inMemoryDB.threatRecords || []).filter(r => r.severity === 'Critical').length + (inMemoryDB.voiceAnalyses || []).filter(v => v.syntheticVoiceRisk === 'Critical').length;
    let highCount = (inMemoryDB.threatRecords || []).filter(r => r.severity === 'High').length;

    try {
      threatCount += await ThreatRecord.countDocuments();
      voiceCount += await VoiceAnalysis.countDocuments();
      criticalCount += await ThreatRecord.countDocuments({ severity: 'Critical' });
    } catch (e) {
      // Mongo not reachable
    }

    const totalEvents = threatCount + voiceCount;
    const computedRisk = totalEvents === 0 ? 0 : Math.min(95, (criticalCount * 30) + (highCount * 15) + (totalEvents * 3));

    res.json({
      success: true,
      data: {
        totalScans: threatCount,
        voiceScans: voiceCount,
        blockchainNotarizations: threatCount + voiceCount,
        activeThreats: criticalCount + highCount,
        riskIndex: computedRisk
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/intelligence/feed
const getIntelligenceFeed = async (req, res) => {
  try {
    const stream = [];

    // Add recent in-memory threat records
    if (inMemoryDB.threatRecords) {
      inMemoryDB.threatRecords.slice(0, 10).forEach(r => {
        stream.push({
          indicator: r.indicator,
          target: r.indicator,
          category: r.threatCategory,
          severity: r.severity,
          timestamp: r.createdAt || new Date()
        });
      });
    }

    // Add recent in-memory voice records
    if (inMemoryDB.voiceAnalyses) {
      inMemoryDB.voiceAnalyses.slice(0, 10).forEach(v => {
        stream.push({
          indicator: v.fileName,
          target: v.fileName,
          category: `Voice-Clone Analysis (${v.syntheticVoiceRisk})`,
          severity: v.syntheticVoiceRisk === 'Critical' ? 'Critical' : v.syntheticVoiceRisk === 'High' ? 'High' : 'Clean',
          timestamp: v.createdAt || new Date()
        });
      });
    }

    // Sort by timestamp descending
    stream.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({
      success: true,
      data: stream
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};


// @route   GET /api/intelligence/mitre
const getMitreMatrix = async (req, res) => {
  try {
    const mitreTactics = [
      {
        techniqueId: 'T1566.002',
        name: 'Spearphishing Link & Credential Harvesting',
        description: 'Adversaries send targeted communications containing deceptive URLs to harvest user credentials and Web3 seed phrases.',
        mitigation: 'CyberShield Deep URL & Shannon entropy engine detects domain generation algorithms and suspicious TLDs before session execution.'
      },
      {
        techniqueId: 'T1656',
        name: 'Impersonation / Deepfake Voice Synthesis',
        description: 'Adversaries use neural vocoders (diffusion/GAN models) to clone executive voices for social engineering and fraudulent wire transfers.',
        mitigation: 'Acoustic glottal pulse, pitch jitter suppression, and mel-spectrogram ceiling cutoff analysis flag synthetic vocal tracts in real-time.'
      },
      {
        techniqueId: 'T1071.001',
        name: 'Application Layer C2 Traffic',
        description: 'Threat actors establish command and control channels masquerading over standard TLS/HTTPS or DNS protocols.',
        mitigation: 'Automated IP subnet risk scoring, bulletproof hosting detection, and TOR exit node telemetry flag unauthorized C2 endpoints.'
      },
      {
        techniqueId: 'T1027',
        name: 'Obfuscated & Packed Executable Payloads',
        description: 'Attackers employ metamorphic crypters and high-entropy packaging to bypass traditional signature scanners.',
        mitigation: 'Cryptographic hash cross-referencing and Shannon entropy binary analysis identify zero-day packed malicious artifacts.'
      },
      {
        techniqueId: 'T1565.001',
        name: 'Stored Log & Audit Manipulation',
        description: 'Intruders alter local security logs, system event viewers, or audit tables to conceal breach footprints and lateral movement.',
        mitigation: 'Immutable Ethereum Sepolia blockchain ledger cryptographic notarization ensures zero audit trail tampering and forensic readiness.'
      },
      {
        techniqueId: 'T1110',
        name: 'Brute Force & Credential Knocking',
        description: 'Botnets execute automated dictionary and spraying attacks against internet-facing SSH, RDP, and API gateways.',
        mitigation: 'Distributed IP reputation engine applies automated perimeter firewall blocks upon detecting anomalous port probing.'
      }
    ];

    res.json({
      success: true,
      data: mitreTactics
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  getDashboardOverview,
  getIntelligenceStats,
  getIntelligenceFeed,
  getMitreMatrix
};
