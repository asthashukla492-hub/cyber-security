/**
 * CyberShield Voice & Audio Visualizer Module
 * Handles Web Audio API Analyser, MediaRecorder, frequency spectrogram animation, and base64 export.
 */

class VoiceVisualizer {
  constructor(canvasId, timerId) {
    this.canvas = document.getElementById(canvasId);
    this.canvasCtx = this.canvas ? this.canvas.getContext('2d') : null;
    this.timerEl = document.getElementById(timerId);

    this.audioCtx = null;
    this.analyser = null;
    this.mediaStream = null;
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.recordedBlob = null;
    this.recordedBase64 = null;

    this.isRecording = false;
    this.animationFrameId = null;
    this.startTime = 0;
    this.timerInterval = null;

    this.initIdleCanvas();
  }

  // Draw idle pulsing aesthetic line before recording begins
  initIdleCanvas() {
    if (!this.canvasCtx) return;
    const width = this.canvas.width;
    const height = this.canvas.height;

    const drawIdle = (time) => {
      if (this.isRecording) return;
      this.canvasCtx.fillStyle = '#05070c';
      this.canvasCtx.fillRect(0, 0, width, height);

      // Grid guidelines
      this.canvasCtx.strokeStyle = 'rgba(0, 240, 255, 0.05)';
      this.canvasCtx.lineWidth = 1;
      this.canvasCtx.beginPath();
      for (let y = 20; y < height; y += 30) {
        this.canvasCtx.moveTo(0, y);
        this.canvasCtx.lineTo(width, y);
      }
      this.canvasCtx.stroke();

      // Cyber sine wave idle pulse
      this.canvasCtx.lineWidth = 2;
      const gradient = this.canvasCtx.createLinearGradient(0, 0, width, 0);
      gradient.addColorStop(0, 'rgba(0, 240, 255, 0.1)');
      gradient.addColorStop(0.5, 'rgba(0, 240, 255, 0.7)');
      gradient.addColorStop(1, 'rgba(157, 78, 221, 0.2)');
      this.canvasCtx.strokeStyle = gradient;

      this.canvasCtx.beginPath();
      const midY = height / 2;
      for (let x = 0; x < width; x += 4) {
        const y = midY + Math.sin(x * 0.03 + (time || 0) * 0.003) * 6;
        if (x === 0) this.canvasCtx.moveTo(x, y);
        else this.canvasCtx.lineTo(x, y);
      }
      this.canvasCtx.stroke();

      this.animationFrameId = requestAnimationFrame(drawIdle);
    };

    drawIdle(0);
  }

  // Start live microphone capture
  async startRecording() {
    try {
      if (this.animationFrameId) cancelAnimationFrame(this.animationFrameId);

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: false,
          autoGainControl: false
        }
      });

      this.mediaStream = stream;
      this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const source = this.audioCtx.createMediaStreamSource(stream);
      this.analyser = this.audioCtx.createAnalyser();
      this.analyser.fftSize = 256;
      source.connect(this.analyser);

      this.audioChunks = [];
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus') 
        ? 'audio/webm;codecs=opus' 
        : 'audio/ogg';

      this.mediaRecorder = new MediaRecorder(stream, { mimeType });
      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) this.audioChunks.push(e.data);
      };

      this.mediaRecorder.start(100);
      this.isRecording = true;
      this.startTime = Date.now();

      // Start timer display
      if (this.timerEl) {
        this.timerInterval = setInterval(() => {
          const elapsed = (Date.now() - this.startTime) / 1000;
          const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
          const secs = (elapsed % 60).toFixed(1).padStart(4, '0');
          this.timerEl.textContent = `${mins}:${secs}`;
        }, 100);
      }

      this.renderVisualizer();
      return true;
    } catch (err) {
      console.error('[VoiceVisualizer] Microphone access error:', err);
      this.initIdleCanvas();
      throw err;
    }
  }

  // Render frequency bars and spectral centroid wave
  renderVisualizer() {
    if (!this.isRecording || !this.analyser) return;

    const bufferLength = this.analyser.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);
    this.analyser.getByteFrequencyData(dataArray);

    const width = this.canvas.width;
    const height = this.canvas.height;
    this.canvasCtx.fillStyle = 'rgba(5, 7, 12, 0.35)';
    this.canvasCtx.fillRect(0, 0, width, height);

    const barWidth = (width / bufferLength) * 2.2;
    let x = 0;

    for (let i = 0; i < bufferLength; i++) {
      const barHeight = (dataArray[i] / 255) * (height - 20);

      // Cyberpunk dual color gradient based on frequency intensity
      const grad = this.canvasCtx.createLinearGradient(0, height, 0, height - barHeight);
      grad.addColorStop(0, 'rgba(0, 240, 255, 0.3)');
      grad.addColorStop(0.7, '#00f0ff');
      grad.addColorStop(1, '#ff0055');

      this.canvasCtx.fillStyle = grad;
      this.canvasCtx.fillRect(x, height - barHeight, barWidth - 1, barHeight);

      // Top glowing spark
      if (barHeight > 10) {
        this.canvasCtx.fillStyle = '#ffffff';
        this.canvasCtx.fillRect(x, height - barHeight - 2, barWidth - 1, 2);
      }

      x += barWidth;
    }

    this.animationFrameId = requestAnimationFrame(() => this.renderVisualizer());
  }

  // Stop recording and package audio into Blob & Base64
  stopRecording() {
    return new Promise((resolve) => {
      if (!this.mediaRecorder || !this.isRecording) {
        return resolve(null);
      }

      clearInterval(this.timerInterval);
      this.isRecording = false;

      this.mediaRecorder.onstop = async () => {
        const mimeType = this.mediaRecorder.mimeType || 'audio/webm';
        this.recordedBlob = new Blob(this.audioChunks, { type: mimeType });

        // Convert to Base64
        const reader = new FileReader();
        reader.readAsDataURL(this.recordedBlob);
        reader.onloadend = () => {
          this.recordedBase64 = reader.result;
          this.cleanupStream();
          this.initIdleCanvas();

          resolve({
            blob: this.recordedBlob,
            base64: this.recordedBase64,
            mimeType: mimeType
          });
        };
      };

      this.mediaRecorder.stop();
    });
  }

  cleanupStream() {
    if (this.mediaStream) {
      this.mediaStream.getTracks().forEach(track => track.stop());
      this.mediaStream = null;
    }
    if (this.audioCtx && this.audioCtx.state !== 'closed') {
      this.audioCtx.close();
      this.audioCtx = null;
    }
  }
}

window.VoiceVisualizer = VoiceVisualizer;
