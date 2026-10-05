import { Fragment, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react';
import { calls } from '../../calls/callManager';
import { formatDay, formatDuration, formatTime, timerLabel, useLang, useT } from '../../i18n';
import { messenger } from '../../state/messenger';
import { toast, useApp } from '../../state/store';
import type { ChatMessage, Contact } from '../../state/types';
import { Avatar } from '../components/Common';
import {
  IconAlert,
  IconArrowDown,
  IconBack,
  IconCallIn,
  IconCallOut,
  IconCheck,
  IconChecks,
  IconClock,
  IconClose,
  IconCopy,
  IconInfo,
  IconLock,
  IconPhone,
  IconReply,
  IconRetry,
  IconSend,
  IconShield,
  IconShieldAlert,
  IconTimer,
  IconTrash,
  IconVideo,
} from '../icons/Icons';

const EMPTY: ChatMessage[] = [];
const GROUP_GAP = 3 * 60 * 1000;

function useNow(ms: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

export function Conversation({ peer, onInfo }: { peer: string; onInfo: () => void }) {
  const t = useT();
  const lang = useLang();
  const contact = useApp((s) => s.contacts[peer]);
  const messages = useApp((s) => s.messages[peer] ?? EMPTY);
  const typingUntil = useApp((s) => s.typing[peer] ?? 0);
  const conn = useApp((s) => s.conn);
  const now = useNow(1000);
  const [replyTo, setReplyTo] = useState<ChatMessage | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [atBottom, setAtBottom] = useState(true);
  const [hasOlder, setHasOlder] = useState(true);
  const scroller = useRef<HTMLDivElement>(null);
  const prevCount = useRef(0);

  // Mark read when new messages arrive while viewing.
  useEffect(() => {
    void messenger.markRead(peer);
  }, [peer, messages.length]);

  useEffect(() => {
    setReplyTo(null);
    setSelected(null);
    setHasOlder(true);
    prevCount.current = 0;
  }, [peer]);

  // Retry failed sends once we're back online.
  useEffect(() => {
    if (conn === 'online') void messenger.retryFailed(peer);
  }, [conn, peer]);

  // Stick to the bottom when new messages arrive and we were at the bottom.
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const last = messages[messages.length - 1];
    const grew = messages.length > prevCount.current;
    if (prevCount.current === 0 || (grew && (atBottom || last?.dir === 'out'))) {
      el.scrollTop = el.scrollHeight;
    }
    prevCount.current = messages.length;
  }, [messages, atBottom]);

  if (!contact) return null;
  const name = contact.nickname || contact.username;
  const typing = typingUntil > now;

  return (
    <section className="conversation" aria-label={name}>
      <header className="conv-head">
        <button className="icon-btn mobile-only" onClick={() => void messenger.open(undefined)} aria-label={t('conv.back')}>
          <IconBack />
        </button>
        <button className="conv-title" onClick={onInfo}>
          <Avatar name={name} hue={contact.hue} size={40} />
          <span className="conv-title-text">
            <span className="conv-name">
              <bdi>{name}</bdi>
              {contact.verified && <IconShield size={15} className="verified-icon" />}
            </span>
            <span className={`conv-sub ${typing ? 'typing' : ''}`}>
              {typing ? (
                <>
                  <span className="dots" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                  {t('conv.typing')}
                </>
              ) : contact.timer > 0 ? (
                <>
                  <IconTimer size={13} /> {t('conv.timerOn', { timer: timerLabel(lang, contact.timer) })}
                </>
              ) : (
                <>
                  <IconLock size={12} /> <bdi dir="ltr">@{contact.username}</bdi>
                </>
              )}
            </span>
          </span>
        </button>
        <div className="conv-actions">
          <button className="icon-btn" onClick={() => void calls.start(peer, false)} aria-label={t('conv.voiceCall')} title={t('conv.voiceCall')} disabled={contact.blocked}>
            <IconPhone />
          </button>
          <button className="icon-btn" onClick={() => void calls.start(peer, true)} aria-label={t('conv.videoCall')} title={t('conv.videoCall')} disabled={contact.blocked}>
            <IconVideo />
          </button>
          <button className="icon-btn" onClick={onInfo} aria-label={t('conv.info')} title={t('conv.info')}>
            <IconInfo />
          </button>
        </div>
      </header>

      {contact.identityChanged && (
        <div className="identity-banner" role="alert">
          <IconShieldAlert size={20} />
          <p>{t('conv.identityBanner', { name })}</p>
          <div className="banner-actions">
            <button className="btn small primary" onClick={onInfo}>
              {t('conv.verifyNow')}
            </button>
            <button className="btn small ghost" onClick={() => void messenger.acknowledgeIdentityChange(peer)}>
              {t('conv.dismiss')}
            </button>
          </div>
        </div>
      )}

      <div
        className="messages"
        ref={scroller}
        onScroll={(e) => {
          const el = e.currentTarget;
          setAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 80);
        }}
        onClick={() => setSelected(null)}
      >
        <div className="e2ee-note">
          <IconLock size={16} />
          <span>{t('conv.e2ee')}</span>
        </div>
        {hasOlder && messages.length >= 200 && (
          <button
            className="load-older"
            onClick={async (e) => {
              e.stopPropagation();
              const el = scroller.current!;
              const h = el.scrollHeight;
              const more = await messenger.loadOlder(peer);
              setHasOlder(more);
              requestAnimationFrame(() => (el.scrollTop = el.scrollHeight - h));
            }}
          >
            {t('conv.loadOlder')}
          </button>
        )}
        {messages.map((m, i) => {
          const prev = messages[i - 1];
          const newDay = !prev || new Date(prev.ts).toDateString() !== new Date(m.ts).toDateString();
          const grouped = !newDay && prev && prev.kind === 'text' && m.kind === 'text' && prev.dir === m.dir && m.ts - prev.ts < GROUP_GAP;
          return (
            <Fragment key={m.id}>
              {newDay && (
                <div className="day-sep">
                  <span>{formatDay(lang, m.ts)}</span>
                </div>
              )}
              <MessageRow
                m={m}
                contact={contact}
                grouped={!!grouped}
                selected={selected === m.id}
                onSelect={() => setSelected(selected === m.id ? null : m.id)}
                onReply={() => {
                  setReplyTo(m);
                  setSelected(null);
                }}
              />
            </Fragment>
          );
        })}
      </div>

      {!atBottom && (
        <button
          className="scroll-down"
          aria-label="↓"
          onClick={() => scroller.current?.scrollTo({ top: scroller.current.scrollHeight, behavior: 'smooth' })}
        >
          <IconArrowDown size={20} />
        </button>
      )}

      {contact.blocked ? (
        <div className="blocked-bar">
          <span>{t('conv.blocked')}</span>
          <button className="btn small" onClick={() => void messenger.setBlocked(peer, false)}>
            {t('conv.unblock')}
          </button>
        </div>
      ) : (
        <Composer peer={peer} replyTo={replyTo} onClearReply={() => setReplyTo(null)} />
      )}
    </section>
  );
}

function MessageRow({
  m,
  contact,
  grouped,
  selected,
  onSelect,
  onReply,
}: {
  m: ChatMessage;
  contact: Contact;
  grouped: boolean;
  selected: boolean;
  onSelect: () => void;
  onReply: () => void;
}) {
  const t = useT();
  const lang = useLang();
  const name = contact.nickname || contact.username;

  if (m.kind === 'system' && m.sys) {
    const params: Record<string, string | number> = { name, ...(m.sys.params ?? {}) };
    if (typeof params.exp === 'number') params.timer = timerLabel(lang, params.exp);
    const alert = m.sys.key === 'sys.identityChanged' || m.sys.key === 'sys.decryptFailed';
    return (
      <div className={`sys-msg ${alert ? 'alert' : ''}`}>
        {alert ? <IconShieldAlert size={14} /> : m.sys.key.startsWith('sys.timer') ? <IconTimer size={14} /> : <IconShield size={14} />}
        <span>{t(m.sys.key, params)}</span>
      </div>
    );
  }

  if (m.kind === 'call' && m.call) {
    const c = m.call;
    const missed = c.outcome === 'missed' || (m.dir === 'in' && c.outcome === 'declined');
    return (
      <div className={`call-msg ${m.dir} ${missed ? 'missed' : ''}`}>
        <span className="call-msg-icon">{m.dir === 'in' ? <IconCallIn size={18} /> : <IconCallOut size={18} />}</span>
        <span className="call-msg-text">
          <strong>{t(`callmsg.${c.video ? 'video' : 'voice'}.${m.dir}`)}</strong>
          <span>
            {c.outcome === 'completed' && c.durationSec !== undefined ? formatDuration(lang, c.durationSec) : t(`callmsg.${c.outcome}`)}
            {' · '}
            {formatTime(lang, m.ts)}
          </span>
        </span>
      </div>
    );
  }

  const out = m.dir === 'out';
  return (
    <div className={`msg-row ${m.dir} ${grouped ? 'grouped' : ''}`}>
      <div
        className={`bubble ${m.status === 'failed' ? 'failed' : ''} ${selected ? 'selected' : ''}`}
        onClick={(e) => {
          e.stopPropagation();
          if (m.status === 'failed') void messenger.retry(m);
          else onSelect();
        }}
        onDoubleClick={onReply}
      >
        {m.replyTo && (
          <div className={`quote ${m.replyTo.dir}`}>
            <span className="quote-who">{m.replyTo.dir === 'out' ? t('chats.you') : name}</span>
            <span className="quote-body" dir="auto">
              {m.replyTo.body}
            </span>
          </div>
        )}
        <div className="body" dir="auto">
          {m.body}
        </div>
        <div className="meta">
          {m.expiresAt && <IconTimer size={12} />}
          <time dateTime={new Date(m.ts).toISOString()}>{formatTime(lang, m.ts)}</time>
          {out && <StatusIcon status={m.status} />}
        </div>
      </div>
      {m.status === 'failed' && (
        <span className="failed-hint">
          <IconAlert size={14} /> {t('conv.failed')}
        </span>
      )}
      {selected && (
        <div className="msg-actions" onClick={(e) => e.stopPropagation()}>
          <button onClick={onReply} title={t('conv.reply')} aria-label={t('conv.reply')}>
            <IconReply size={18} />
          </button>
          <button
            onClick={() => {
              void navigator.clipboard?.writeText(m.body).then(() => toast('conv.copied'));
              onSelect();
            }}
            title={t('conv.copy')}
            aria-label={t('conv.copy')}
          >
            <IconCopy size={18} />
          </button>
          {m.status === 'failed' && (
            <button onClick={() => void messenger.retry(m)} title={t('conv.retry')} aria-label={t('conv.retry')}>
              <IconRetry size={18} />
            </button>
          )}
          <button onClick={() => void messenger.deleteLocal(m)} title={t('conv.deleteForMe')} aria-label={t('conv.deleteForMe')}>
            <IconTrash size={18} />
          </button>
          {out && m.status !== 'failed' && (
            <button className="danger" onClick={() => void messenger.deleteForEveryone(m)} title={t('conv.deleteForAll')}>
              <IconTrash size={18} />
              <span>{t('conv.deleteForAll')}</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function StatusIcon({ status }: { status: ChatMessage['status'] }) {
  const t = useT();
  const label = t(`status.${status}`);
  switch (status) {
    case 'pending':
      return <IconClock size={14} aria-label={label} className="st pending" />;
    case 'sent':
      return <IconCheck size={15} aria-label={label} className="st" />;
    case 'delivered':
      return <IconChecks size={16} aria-label={label} className="st" />;
    case 'read':
      return <IconChecks size={16} aria-label={label} className="st read" />;
    case 'failed':
      return <IconAlert size={14} aria-label={label} className="st failed" />;
  }
}

function Composer({ peer, replyTo, onClearReply }: { peer: string; replyTo: ChatMessage | null; onClearReply: () => void }) {
  const t = useT();
  const enterToSend = useApp((s) => s.settings.enterToSend);
  const contact = useApp((s) => s.contacts[peer]);
  const [text, setText] = useState('');
  const ref = useRef<HTMLTextAreaElement>(null);

  // Per-conversation drafts kept in memory only.
  const drafts = useRef(new Map<string, string>());
  useEffect(() => {
    setText(drafts.current.get(peer) ?? '');
    ref.current?.focus();
  }, [peer]);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 180)}px`;
  }, [text]);

  useEffect(() => {
    if (replyTo) ref.current?.focus();
  }, [replyTo]);

  function send() {
    const body = text.trim();
    if (!body) return;
    void messenger.sendText(peer, body, replyTo ?? undefined);
    messenger.typing(peer, false);
    setText('');
    drafts.current.delete(peer);
    onClearReply();
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing && (enterToSend || e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      send();
    }
    if (e.key === 'Escape' && replyTo) onClearReply();
  }

  const name = contact?.nickname || contact?.username || peer;

  return (
    <div className="composer-wrap">
      {replyTo && (
        <div className="reply-preview">
          <IconReply size={18} />
          <div>
            <span className="quote-who">
              {t('conv.replyingTo')} {replyTo.dir === 'out' ? t('chats.you') : name}
            </span>
            <span className="quote-body" dir="auto">
              {replyTo.body}
            </span>
          </div>
          <button className="icon-btn" onClick={onClearReply} aria-label={t('common.close')}>
            <IconClose size={18} />
          </button>
        </div>
      )}
      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <textarea
          ref={ref}
          rows={1}
          dir="auto"
          value={text}
          placeholder={t('conv.placeholder')}
          aria-label={t('conv.placeholder')}
          maxLength={8000}
          onChange={(e) => {
            setText(e.target.value);
            drafts.current.set(peer, e.target.value);
            messenger.typing(peer, e.target.value.length > 0);
          }}
          onKeyDown={onKey}
          onBlur={() => messenger.typing(peer, false)}
        />
        <button className="send-btn" type="submit" disabled={!text.trim()} aria-label={t('conv.send')} title={t('conv.send')}>
          <IconSend size={20} className="flip-rtl" />
        </button>
      </form>
    </div>
  );
}

export function EmptyConversation() {
  const t = useT();
  return (
    <section className="conversation empty">
      <div className="empty-state">
        <div className="empty-orb" aria-hidden="true">
          <IconLock size={34} />
        </div>
        <h2>{t('conv.select')}</h2>
        <p>{t('conv.selectHint')}</p>
      </div>
    </section>
  );
}
