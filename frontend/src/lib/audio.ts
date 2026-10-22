const TARGET_SAMPLE_RATE = 16_000;
const CHUNK_SECONDS = 3;

export interface MicCapture {
  stop: () => Promise<void>;
}

export interface MicCaptureOptions {
  onChunk: (wav: Blob) => void;
  onLevel: (rms: number) => void;
}

/** Downsample a mono buffer while averaging source samples to reduce aliasing. */
export function downsampleMono(input: Float32Array, sourceRate: number, targetRate = TARGET_SAMPLE_RATE): Float32Array {
  if (sourceRate === targetRate) return input.slice();
  const outputLength = Math.max(1, Math.round(input.length * targetRate / sourceRate));
  const output = new Float32Array(outputLength);
  const ratio = sourceRate / targetRate;

  for (let i = 0; i < outputLength; i += 1) {
    const start = i * ratio;
    const end = Math.min(input.length, (i + 1) * ratio);
    const first = Math.floor(start);
    const last = Math.ceil(end);
    let total = 0;
    let weight = 0;
    for (let j = first; j < last; j += 1) {
      const overlap = Math.max(0, Math.min(end, j + 1) - Math.max(start, j));
      total += (input[j] ?? 0) * overlap;
      weight += overlap;
    }
    output[i] = weight ? total / weight : 0;
  }
  return output;
}

/** Encode normalized mono samples as a standard 44-byte-header PCM16 WAV. */
export function encodePcm16Wav(samples: Float32Array, sampleRate = TARGET_SAMPLE_RATE): ArrayBuffer {
  const bytesPerSample = 2;
  const dataSize = samples.length * bytesPerSample;
  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);

  const ascii = (offset: number, value: string) => {
    for (let i = 0; i < value.length; i += 1) view.setUint8(offset + i, value.charCodeAt(i));
  };
  ascii(0, "RIFF");
  view.setUint32(4, 36 + dataSize, true);
  ascii(8, "WAVE");
  ascii(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, 1, true); // mono
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * bytesPerSample, true);
  view.setUint16(32, bytesPerSample, true);
  view.setUint16(34, 16, true);
  ascii(36, "data");
  view.setUint32(40, dataSize, true);

  for (let i = 0; i < samples.length; i += 1) {
    const sample = Math.max(-1, Math.min(1, samples[i] ?? 0));
    view.setInt16(44 + i * 2, sample < 0 ? sample * 0x8000 : sample * 0x7fff, true);
  }
  return buffer;
}

function join(parts: Float32Array[], length: number): Float32Array {
  const joined = new Float32Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

/**
 * Capture unprocessed speakerphone audio and emit self-contained, 16 kHz mono
 * WAV files. AudioWorklet is preferred; ScriptProcessor is the compatibility
 * fallback for older demo browsers.
 */
export async function startMicCapture({ onChunk, onLevel }: MicCaptureOptions): Promise<MicCapture> {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: true },
  });
  const context = new AudioContext();
  const source = context.createMediaStreamSource(stream);
  const silentGain = context.createGain();
  silentGain.gain.value = 0;
  silentGain.connect(context.destination);

  const sourceFramesPerChunk = Math.round(context.sampleRate * CHUNK_SECONDS);
  let parts: Float32Array[] = [];
  let bufferedFrames = 0;
  let stopped = false;
  let lastLevelAt = 0;

  const emit = (sourceSamples: Float32Array) => {
    if (!sourceSamples.length) return;
    const samples = downsampleMono(sourceSamples, context.sampleRate, TARGET_SAMPLE_RATE);
    onChunk(new Blob([encodePcm16Wav(samples, TARGET_SAMPLE_RATE)], { type: "audio/wav" }));
  };

  const consume = (incoming: Float32Array) => {
    if (stopped) return;
    parts.push(incoming.slice());
    bufferedFrames += incoming.length;

    const now = performance.now();
    if (now - lastLevelAt >= 50) {
      let energy = 0;
      for (let i = 0; i < incoming.length; i += 1) energy += incoming[i] * incoming[i];
      onLevel(Math.min(1, Math.sqrt(energy / Math.max(1, incoming.length))));
      lastLevelAt = now;
    }

    while (bufferedFrames >= sourceFramesPerChunk) {
      const all = join(parts, bufferedFrames);
      emit(all.slice(0, sourceFramesPerChunk));
      const remainder = all.slice(sourceFramesPerChunk);
      parts = remainder.length ? [remainder] : [];
      bufferedFrames = remainder.length;
    }
  };

  let processor: AudioWorkletNode | ScriptProcessorNode;
  let workletUrl: string | null = null;
  if (context.audioWorklet && typeof AudioWorkletNode !== "undefined") {
    const workletSource = `
      class ScamShieldCapture extends AudioWorkletProcessor {
        process(inputs) {
          const channel = inputs[0] && inputs[0][0];
          if (channel) this.port.postMessage(channel.slice());
          return true;
        }
      }
      registerProcessor('scamshield-capture', ScamShieldCapture);
    `;
    workletUrl = URL.createObjectURL(new Blob([workletSource], { type: "text/javascript" }));
    try {
      await context.audioWorklet.addModule(workletUrl);
      const worklet = new AudioWorkletNode(context, "scamshield-capture", { channelCount: 1 });
      worklet.port.onmessage = (event: MessageEvent<Float32Array>) => consume(event.data);
      processor = worklet;
    } catch {
      const fallback = context.createScriptProcessor(4096, 1, 1);
      fallback.onaudioprocess = (event) => consume(event.inputBuffer.getChannelData(0));
      processor = fallback;
    } finally {
      URL.revokeObjectURL(workletUrl);
      workletUrl = null;
    }
  } else {
    const fallback = context.createScriptProcessor(4096, 1, 1);
    fallback.onaudioprocess = (event) => consume(event.inputBuffer.getChannelData(0));
    processor = fallback;
  }

  source.connect(processor);
  processor.connect(silentGain);
  if (context.state === "suspended") await context.resume();

  return {
    stop: async () => {
      if (stopped) return;
      stopped = true;
      source.disconnect();
      processor.disconnect();
      if ("port" in processor) processor.port.onmessage = null;
      if ("onaudioprocess" in processor) processor.onaudioprocess = null;
      stream.getTracks().forEach((track) => track.stop());
      // Preserve the last spoken phrase when the user stops between 4 s boundaries.
      if (bufferedFrames >= context.sampleRate / 4) emit(join(parts, bufferedFrames));
      parts = [];
      bufferedFrames = 0;
      onLevel(0);
      await context.close();
    },
  };
}

