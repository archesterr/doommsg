import { useEffect, useRef, useState } from 'react';
import { calls, useCall } from '../../calls/callManager';
import { formatDuration, useLang, useT } from '../../i18n';
import { useApp } from '../../state/store';
import { Avatar } from '../components/Common';
import { IconFlip, IconHangup, IconLock, IconMic, IconMicOff, IconPhone, IconVideo, IconVideoOff } from '../icons/Icons';

function Media({ stream, muted, className }: { stream?: MediaStream; muted?: boolean; className?: string }) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (ref.current && ref.current.srcObject !== (stream ?? null)) ref.current.srcObject = stream ?? null;
  }, [stream]);
  return <video ref={ref} className={className} autoPlay playsInline muted={muted} />;
}

export function CallScreen() {
  const t = useT();
  const lang = useLang();
  const s = useCall();
  const contact = useApp((st) => (s.peer ? st.contacts[s.peer] : undefined));
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (s.phase !== 'active') return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [s.phase]);

  if (s.phase === 'idle' || !s.peer) return null;
  const name = contact?.nickname || s.peer;
  const hue = contact?.hue ?? 200;
  const localVideo = !!s.local?.getVideoTracks().length && !s.cameraOff;
  const showRemoteVideo = s.remoteVideo && s.phase === 'active';

  let status: string;
  switch (s.phase) {
    case 'outgoing':
      status = s.ringing ? t('call.ringing') : t('call.calling');
      break;
    case 'incoming':
      status = s.video ? t('call.incomingVideo') : t('call.incomingVoice');
      break;
    case 'connecting':
      status = t('call.connecting');
      break;
    default:
      status =
        s.quality === 'reconnecting'
          ? t('call.reconnecting')
          : formatDuration(lang, Math.max(0, Math.round((now - (s.startedAt ?? now)) / 1000)));
  }

  return (
    <div className={`call-screen ${showRemoteVideo ? 'has-video' : ''}`} role="dialog" aria-modal="true" aria-label={status}>
      <div className="call-bg" style={{ ['--h' as string]: hue }} aria-hidden="true" />
      {/* Remote audio always plays through this element, video or not. */}
      <Media stream={s.remote} className={`remote-video ${showRemoteVideo ? '' : 'hidden'}`} />

      <div className="call-top">
        <span className="e2ee-chip">
          <IconLock size={13} /> {t('call.e2ee')}
        </span>
        {s.phase === 'active' && s.quality === 'poor' && <span className="quality-chip">{t('call.poor')}</span>}
      </div>

      {!showRemoteVideo && (
        <div className="call-center">
          <div className={`ring-wrap ${s.phase === 'incoming' || s.phase === 'outgoing' ? 'ringing' : ''}`}>
            <Avatar name={name} hue={hue} size={120} />
          </div>
          <h2>
            <bdi>{name}</bdi>
          </h2>
          <p className="call-status">{status}</p>
        </div>
      )}
      {showRemoteVideo && (
        <div className="call-overlay-info">
          <strong>
            <bdi>{name}</bdi>
          </strong>
          <span>{status}</span>
        </div>
      )}

      {localVideo && <Media stream={s.local} muted className="local-video" />}

      <div className="call-controls">
        {s.phase === 'incoming' ? (
          <>
            <button className="call-btn decline" onClick={() => void calls.decline()} aria-label={t('call.decline')}>
              <IconHangup size={28} />
              <span>{t('call.decline')}</span>
            </button>
            <button className="call-btn accept" onClick={() => void calls.accept()} aria-label={t('call.accept')}>
              {s.video ? <IconVideo size={28} /> : <IconPhone size={28} />}
              <span>{t('call.accept')}</span>
            </button>
          </>
        ) : (
          <>
            <button className={`call-btn ${s.muted ? 'on' : ''}`} onClick={() => calls.toggleMute()} aria-pressed={s.muted} aria-label={s.muted ? t('call.unmute') : t('call.mute')}>
              {s.muted ? <IconMicOff size={24} /> : <IconMic size={24} />}
            </button>
            <button
              className={`call-btn ${!localVideo ? 'on' : ''}`}
              onClick={() => void calls.toggleCamera()}
              aria-label={localVideo ? t('call.cameraOff') : t('call.cameraOn')}
            >
              {localVideo ? <IconVideo size={24} /> : <IconVideoOff size={24} />}
            </button>
            {localVideo && (
              <button className="call-btn" onClick={() => void calls.switchCamera()} aria-label={t('call.flip')}>
                <IconFlip size={24} />
              </button>
            )}
            <button className="call-btn decline" onClick={() => void calls.hangup()} aria-label={t('call.hangup')}>
              <IconHangup size={28} />
            </button>
          </>
        )}
      </div>
    </div>
  );
}
