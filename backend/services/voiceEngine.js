const crypto = require('crypto');

let decoderPromise = null;

/**
 * Real acoustic analysis engine.
 *
 * IMPORTANT:
 * This is feature-based forensic analysis, NOT a trained
 * deepfake classifier. The returned risk score is a heuristic
 * indicator based on measurable acoustic characteristics.
 */

async function decodeAudio(buffer) {
  if (!decoderPromise) {
    decoderPromise = import('@audio/decode');
  }

  const { default: decode } = await decoderPromise;

  const result = await decode(buffer);

  if (!result || !result.channelData || !result.channelData.length) {
    throw new Error('Unable to decode audio samples');
  }

  return {
    samples: result.channelData[0],
    sampleRate: result.sampleRate
  };
}

/* ----------------------------- */
/* Basic statistics               */
/* ----------------------------- */

function rms(samples) {
  let sum = 0;

  for (let i = 0; i < samples.length; i++) {
    sum += samples[i] * samples[i];
  }

  return Math.sqrt(sum / Math.max(1, samples.length));
}

function zeroCrossingRate(samples) {
  if (samples.length < 2) return 0;

  let crossings = 0;

  for (let i = 1; i < samples.length; i++) {
    if (
      (samples[i - 1] < 0 && samples[i] >= 0) ||
      (samples[i - 1] >= 0 && samples[i] < 0)
    ) {
      crossings++;
    }
  }

  return crossings / (samples.length - 1);
}

function meanAbsolute(samples) {
  let sum = 0;

  for (let i = 0; i < samples.length; i++) {
    sum += Math.abs(samples[i]);
  }

  return sum / Math.max(1, samples.length);
}

/* ----------------------------- */
/* FFT                            */
/* ----------------------------- */

function fftReal(input) {
  const n = input.length;

  if ((n & (n - 1)) !== 0) {
    throw new Error('FFT size must be a power of two');
  }

  const real = new Float64Array(n);
  const imag = new Float64Array(n);

  real.set(input);

  // Bit reversal
  for (let i = 0, j = 0; i < n; i++) {
    if (i < j) {
      const temp = real[i];
      real[i] = real[j];
      real[j] = temp;
    }

    let bit = n >> 1;

    while (j & bit) {
      j ^= bit;
      bit >>= 1;
    }

    j ^= bit;
  }

  for (let length = 2; length <= n; length <<= 1) {
    const angle = -2 * Math.PI / length;
    const wLenReal = Math.cos(angle);
    const wLenImag = Math.sin(angle);

    for (let i = 0; i < n; i += length) {
      let wReal = 1;
      let wImag = 0;

      const half = length >> 1;

      for (let j = 0; j < half; j++) {
        const evenIndex = i + j;
        const oddIndex = i + j + half;

        const oddReal =
          real[oddIndex] * wReal -
          imag[oddIndex] * wImag;

        const oddImag =
          real[oddIndex] * wImag +
          imag[oddIndex] * wReal;

        real[oddIndex] = real[evenIndex] - oddReal;
        imag[oddIndex] = imag[evenIndex] - oddImag;

        real[evenIndex] += oddReal;
        imag[evenIndex] += oddImag;

        const nextWReal =
          wReal * wLenReal -
          wImag * wLenImag;

        const nextWImag =
          wReal * wLenImag +
          wImag * wLenReal;

        wReal = nextWReal;
        wImag = nextWImag;
      }
    }
  }

  return { real, imag };
}

/* ----------------------------- */
/* Spectral features              */
/* ----------------------------- */

function spectralFeatures(samples, sampleRate) {
  const maxFFT = 4096;

  let fftSize = 1024;

  while (
    fftSize * 2 <= maxFFT &&
    fftSize * 2 <= samples.length
  ) {
    fftSize *= 2;
  }

  if (fftSize < 256) {
    return {
      centroid: 0,
      flatness: 0,
      rolloff: 0,
      highFrequencyRatio: 0
    };
  }

  const frame = new Float64Array(fftSize);

  const start = Math.max(
    0,
    Math.floor(samples.length / 2 - fftSize / 2)
  );

  for (let i = 0; i < fftSize; i++) {
    const index = start + i;

    // Hann window
    const window =
      0.5 *
      (1 -
        Math.cos(
          (2 * Math.PI * i) / (fftSize - 1)
        ));

    frame[i] =
      (samples[index] || 0) * window;
  }

  const { real, imag } = fftReal(frame);

  const bins = Math.floor(fftSize / 2);

  let totalEnergy = 0;
  let weightedFrequency = 0;

  const magnitudes = new Float64Array(bins);

  for (let i = 0; i < bins; i++) {
    const magnitude =
      Math.sqrt(
        real[i] * real[i] +
        imag[i] * imag[i]
      );

    const power = magnitude * magnitude;

    magnitudes[i] = power;

    const frequency =
      (i * sampleRate) / fftSize;

    totalEnergy += power;
    weightedFrequency += frequency * power;
  }

  if (totalEnergy <= 0) {
    return {
      centroid: 0,
      flatness: 0,
      rolloff: 0,
      highFrequencyRatio: 0
    };
  }

  const centroid =
    weightedFrequency / totalEnergy;

  // Spectral flatness = geometric mean / arithmetic mean
  let logSum = 0;
  let arithmeticSum = 0;

  for (let i = 1; i < bins; i++) {
    const value = Math.max(
      magnitudes[i],
      1e-12
    );

    logSum += Math.log(value);
    arithmeticSum += value;
  }

  const count = Math.max(1, bins - 1);

  const geometricMean =
    Math.exp(logSum / count);

  const arithmeticMean =
    arithmeticSum / count;

  const flatness =
    arithmeticMean > 0
      ? geometricMean / arithmeticMean
      : 0;

  // 85% spectral rolloff
  const target = totalEnergy * 0.85;

  let cumulative = 0;
  let rolloffBin = 0;

  for (let i = 0; i < bins; i++) {
    cumulative += magnitudes[i];

    if (cumulative >= target) {
      rolloffBin = i;
      break;
    }
  }

  const rolloff =
    (rolloffBin * sampleRate) / fftSize;

  // Energy above 6 kHz
  let highFrequencyEnergy = 0;

  for (let i = 0; i < bins; i++) {
    const frequency =
      (i * sampleRate) / fftSize;

    if (frequency >= 6000) {
      highFrequencyEnergy += magnitudes[i];
    }
  }

  const highFrequencyRatio =
    highFrequencyEnergy / totalEnergy;

  return {
    centroid,
    flatness,
    rolloff,
    highFrequencyRatio
  };
}

/* ----------------------------- */
/* Pitch estimation               */
/* ----------------------------- */

function estimatePitch(samples, sampleRate) {
  const minFrequency = 70;
  const maxFrequency = 350;

  const minLag =
    Math.floor(sampleRate / maxFrequency);

  const maxLag =
    Math.floor(sampleRate / minFrequency);

  const maxSamples = Math.min(
    samples.length,
    sampleRate * 0.5
  );

  if (maxSamples < maxLag * 2) {
    return 0;
  }

  let bestLag = 0;
  let bestCorrelation = -Infinity;

  for (
    let lag = minLag;
    lag <= maxLag;
    lag++
  ) {
    let numerator = 0;
    let energyA = 0;
    let energyB = 0;

    const limit = Math.min(
      maxSamples - lag,
      12000
    );

    for (let i = 0; i < limit; i++) {
      const a = samples[i];
      const b = samples[i + lag];

      numerator += a * b;
      energyA += a * a;
      energyB += b * b;
    }

    const denominator =
      Math.sqrt(energyA * energyB) + 1e-12;

    const correlation =
      numerator / denominator;

    if (correlation > bestCorrelation) {
      bestCorrelation = correlation;
      bestLag = lag;
    }
  }

  if (
    bestLag === 0 ||
    bestCorrelation < 0.25
  ) {
    return 0;
  }

  return sampleRate / bestLag;
}

/* ----------------------------- */
/* Pitch variation                */
/* ----------------------------- */

function pitchVariation(samples, sampleRate) {
  const frameSize =
    Math.floor(sampleRate * 0.04);

  const hopSize =
    Math.floor(sampleRate * 0.02);

  const pitches = [];

  for (
    let start = 0;
    start + frameSize <= samples.length;
    start += hopSize
  ) {
    const frame =
      samples.subarray(
        start,
        start + frameSize
      );

    const energy = rms(frame);

    if (energy < 0.01) continue;

    const pitch =
      estimatePitch(frame, sampleRate);

    if (
      pitch >= 70 &&
      pitch <= 350
    ) {
      pitches.push(pitch);
    }

    // Avoid excessive CPU usage
    if (pitches.length >= 80) break;
  }

  if (pitches.length < 3) {
    return {
      averagePitch: 0,
      jitterPercent: 0
    };
  }

  let mean = 0;

  for (const pitch of pitches) {
    mean += pitch;
  }

  mean /= pitches.length;

  let variation = 0;

  for (const pitch of pitches) {
    variation +=
      Math.abs(pitch - mean);
  }

  variation /=
    pitches.length;

  const jitterPercent =
    (variation / mean) * 100;

  return {
    averagePitch: mean,
    jitterPercent
  };
}

/* ----------------------------- */
/* Frame shimmer estimate         */
/* ----------------------------- */

function estimateShimmer(samples, sampleRate) {
  const frameSize =
    Math.floor(sampleRate * 0.04);

  const hopSize =
    Math.floor(sampleRate * 0.02);

  const amplitudes = [];

  for (
    let start = 0;
    start + frameSize <= samples.length;
    start += hopSize
  ) {
    const frame =
      samples.subarray(
        start,
        start + frameSize
      );

    const value = rms(frame);

    if (value > 0.005) {
      amplitudes.push(value);
    }

    if (amplitudes.length >= 100) {
      break;
    }
  }

  if (amplitudes.length < 3) {
    return 0;
  }

  let differences = 0;
  let reference = 0;

  for (let i = 1; i < amplitudes.length; i++) {
    differences +=
      Math.abs(
        amplitudes[i] -
        amplitudes[i - 1]
      );

    reference +=
      (amplitudes[i] +
        amplitudes[i - 1]) /
      2;
  }

  if (reference === 0) return 0;

  return (
    (differences / reference) *
    100
  );
}

/* ----------------------------- */
/* Main analysis                  */
/* ----------------------------- */

async function analyzeAudioBuffer(
  buffer,
  originalname = 'sample',
  mimetype = 'audio/unknown'
) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error(
      'Audio input must be a Buffer'
    );
  }

  if (buffer.length < 1000) {
    throw new Error(
      'Audio recording is too short for analysis'
    );
  }

  const fileHash =
    crypto
      .createHash('sha256')
      .update(buffer)
      .digest('hex');

  const {
    samples,
    sampleRate
  } = await decodeAudio(buffer);

  if (!samples || samples.length < 1000) {
    throw new Error(
      'Not enough decoded audio samples'
    );
  }

  // Limit processing to approximately 30 seconds
  const maxSamples =
    Math.min(
      samples.length,
      sampleRate * 30
    );

  const analysisSamples =
    samples.subarray(
      0,
      maxSamples
    );

  const rmsValue =
    rms(analysisSamples);

  const zcr =
    zeroCrossingRate(
      analysisSamples
    );

  const meanAbs =
    meanAbsolute(
      analysisSamples
    );

  const spectrum =
    spectralFeatures(
      analysisSamples,
      sampleRate
    );

  const pitch =
    pitchVariation(
      analysisSamples,
      sampleRate
    );

  const shimmer =
    estimateShimmer(
      analysisSamples,
      sampleRate
    );

  /*
   * Estimate harmonic/noise ratio from
   * periodicity around the fundamental.
   */
  let hnr = 0;

  if (pitch.averagePitch > 0) {
    const lag =
      Math.round(
        sampleRate /
        pitch.averagePitch
      );

    let correlation = 0;

    const limit =
      Math.min(
        analysisSamples.length - lag,
        30000
      );

    let numerator = 0;
    let energyA = 0;
    let energyB = 0;

    for (let i = 0; i < limit; i++) {
      const a =
        analysisSamples[i];

      const b =
        analysisSamples[i + lag];

      numerator += a * b;
      energyA += a * a;
      energyB += b * b;
    }

    correlation =
      numerator /
      (Math.sqrt(
        energyA * energyB
      ) + 1e-12);

    correlation =
      Math.max(
        0.0001,
        Math.min(0.9999, correlation)
      );

    hnr =
      10 *
      Math.log10(
        correlation /
        (1 - correlation)
      );

    hnr =
      Math.max(
        -10,
        Math.min(40, hnr)
      );
  }

  /*
   * Feature-based heuristic.
   *
   * This is intentionally conservative.
   * It is NOT a probability of AI generation.
   */
  let riskScore = 0;
  const anomalies = [];

  if (
    pitch.jitterPercent > 0 &&
    pitch.jitterPercent < 0.25
  ) {
    riskScore += 12;

    anomalies.push({
      name:
        'Very Low Pitch Variation',
      severity: 'Low',
      score: 12,
      description:
        'Measured pitch variation is unusually low in the analyzed voiced frames.'
    });
  }

  if (
    spectrum.highFrequencyRatio < 0.015 &&
    spectrum.rolloff < 6000
  ) {
    riskScore += 10;

    anomalies.push({
      name:
        'Reduced High-Frequency Energy',
      severity: 'Low',
      score: 10,
      description:
        'The recording contains relatively little energy in the upper frequency range.'
    });
  }

  if (
    spectrum.flatness > 0.65
  ) {
    riskScore += 8;

    anomalies.push({
      name:
        'High Spectral Noise Content',
      severity: 'Low',
      score: 8,
      description:
        'The measured spectrum contains comparatively noise-like energy.'
    });
  }

  if (
    pitch.averagePitch > 0 &&
    hnr > 30
  ) {
    riskScore += 6;

    anomalies.push({
      name:
        'Strong Periodicity',
      severity: 'Low',
      score: 6,
      description:
        'The measured waveform shows strong periodicity around the estimated fundamental frequency.'
    });
  }

  if (
    shimmer > 8
  ) {
    riskScore += 8;

    anomalies.push({
      name:
        'Amplitude Instability',
      severity: 'Low',
      score: 8,
      description:
        'Frame-to-frame amplitude variation is relatively high.'
    });
  }

  /*
   * Very noisy recordings should not automatically
   * be considered synthetic.
   */
  const qualityWarnings = [];

  if (rmsValue < 0.005) {
    qualityWarnings.push(
      'Very low recording level'
    );
  }

  if (rmsValue > 0.8) {
    qualityWarnings.push(
      'Possible clipping or excessive gain'
    );
  }

  if (zcr > 0.25) {
    qualityWarnings.push(
      'High zero-crossing rate'
    );
  }

  /*
   * Keep this as an acoustic risk indicator,
   * not a fake "AI confidence".
   */
  riskScore =
    Math.max(
      0,
      Math.min(40, Math.round(riskScore))
    );

  const authenticityScore =
    100 - riskScore;

  let syntheticVoiceRisk =
    'Low';

  let verdict =
    'No strong synthetic acoustic indicators detected';

  let recommendation =
    'No strong synthetic indicators were detected. For sensitive actions, use an independent authentication factor.';

  if (riskScore >= 25) {
    syntheticVoiceRisk =
      'Moderate';

    verdict =
      'Multiple acoustic indicators require secondary verification';

    recommendation =
      'Use secondary authentication before high-risk actions. This acoustic analysis is not sufficient by itself to establish synthetic speech.';
  } else if (riskScore >= 12) {
    syntheticVoiceRisk =
      'Low-Moderate';

    verdict =
      'Some acoustic irregularities detected';

    recommendation =
      'Treat the result as a forensic signal only and consider a second authentication factor.';
  }

  if (qualityWarnings.length > 0) {
    recommendation +=
      ` Recording quality: ${qualityWarnings.join(
        '; '
      )}.`;
  }

  /*
   * The "confidence" value is deliberately tied
   * to measurement quality, NOT generated from a hash.
   */
  let confidenceScore = 70;

  if (pitch.averagePitch > 0) {
    confidenceScore += 8;
  }

  if (spectrum.rolloff > 0) {
    confidenceScore += 6;
  }

  if (samples.length > sampleRate * 2) {
    confidenceScore += 8;
  }

  confidenceScore =
    Math.max(
      50,
      Math.min(92, confidenceScore)
    );

  return {
    fileName: originalname,
    fileSize: buffer.length,
    format: mimetype,

    authenticityScore:
      Math.round(authenticityScore),

    syntheticVoiceRisk,

    confidenceScore:
      Math.round(confidenceScore),

    riskScore:
      Math.round(riskScore),

    detectedAnomalies:
      anomalies.length > 0
        ? anomalies
        : [
            {
              name:
                'Natural Acoustic Variation',
              severity:
                'Clean',
              score: 0,
              description:
                'No strong synthetic acoustic indicators were detected by the feature-based analysis.'
            }
          ],

    metrics: {
      pitchJitterPercent:
        Number(
          pitch.jitterPercent.toFixed(2)
        ),

      shimmerPercent:
        Number(
          shimmer.toFixed(2)
        ),

      harmonicToNoiseRatio:
        Number(
          hnr.toFixed(1)
        ),

      spectralFlatness:
        Number(
          spectrum.flatness.toFixed(4)
        ),

      neuralVocoderArtifacts:
        Math.round(
          riskScore
        ),

      phaseDiscontinuity:
        Number(
          (spectrum.highFrequencyRatio * 100).toFixed(1)
        ),

      // Additional real measurements
      rms:
        Number(
          rmsValue.toFixed(5)
        ),

      zeroCrossingRate:
        Number(
          zcr.toFixed(5)
        ),

      spectralCentroidHz:
        Number(
          spectrum.centroid.toFixed(1)
        ),

      spectralRolloffHz:
        Number(
          spectrum.rolloff.toFixed(1)
        ),

      highFrequencyEnergyRatio:
        Number(
          spectrum.highFrequencyRatio.toFixed(4)
        ),

      estimatedFundamentalHz:
        Number(
          pitch.averagePitch.toFixed(1)
        ),

      sampleRate,
      analyzedSamples:
        analysisSamples.length
    },

    verdict,
    recommendation,

    audioFingerprint:
      fileHash
  };
}

module.exports = {
  analyzeAudioBuffer
};
