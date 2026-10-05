// Ring and ringback tones synthesised with WebAudio (no audio assets).

let ctx: AudioContext | null = null;
let stopCurrent: (() => void) | null = null;

function audio(): AudioContext {
  ctx ??= new AudioContext();
  if (ctx.state === 'suspended') void ctx.resume();
  return ctx;
}

function pattern(freqs: number[], onMs: number, offMs: number, gain: number): () => void {
  const ac = audio();
  const out = ac.createGain();
  out.gain.value = 0;
  out.connect(ac.destination);
  const oscs = freqs.map((f) => {
    const o = ac.createOscillator();
    o.type = 'sine';
    o.frequency.value = f;
    o.connect(out);
    o.start();
    return o;
  });
  let on = false;
  const tick = () => {
    on = !on;
    const t = ac.currentTime;
    out.gain.cancelScheduledValues(t);
    out.gain.setTargetAtTime(on ? gain : 0, t, 0.015);
    timer = setTimeout(tick, on ? onMs : offMs);
  };
  let timer = setTimeout(tick, 0);
  return () => {
    clearTimeout(timer);
    out.gain.setTargetAtTime(0, ac.currentTime, 0.01);
    setTimeout(() => {
      oscs.forEach((o) => o.stop());
      out.disconnect();
    }, 100);
  };
}

export function playRingback(): void {
  stopTone();
  stopCurrent = pattern([440, 480], 2000, 4000, 0.05);
}

export function playRingtone(): void {
  stopTone();
  stopCurrent = pattern([660, 880], 400, 300, 0.07);
}

export function playEndTone(): void {
  stopTone();
  const stop = pattern([480, 620], 180, 120, 0.05);
  setTimeout(stop, 700);
}

export function stopTone(): void {
  stopCurrent?.();
  stopCurrent = null;
}
