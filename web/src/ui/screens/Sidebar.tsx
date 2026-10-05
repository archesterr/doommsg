import { useMemo, useState, type FormEvent } from 'react';
import { formatShort, useLang, useT } from '../../i18n';
import { ApiError } from '../../net/api';
import { messenger } from '../../state/messenger';
import { useApp } from '../../state/store';
import type { Contact } from '../../state/types';
import { Avatar, Logo } from '../components/Common';
import { IconPlus, IconSearch, IconSettings, IconShield, IconTimer } from '../icons/Icons';

export function Sidebar({ onSettings }: { onSettings: () => void }) {
  const t = useT();
  const lang = useLang();
  const contacts = useApp((s) => s.contacts);
  const active = useApp((s) => s.active);
  const conn = useApp((s) => s.conn);
  const typing = useApp((s) => s.typing);
  const [q, setQ] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const query = q.trim().replace(/^@/, '').toLowerCase();
  const list = useMemo(() => {
    const all = Object.values(contacts)
      .filter((c) => !c.hidden)
      .sort((a, b) => b.lastTs - a.lastTs);
    if (!query) return all;
    return all.filter((c) => c.username.includes(query) || c.nickname?.toLowerCase().includes(query));
  }, [contacts, query]);

  const canAdd = /^[a-z0-9_]{3,32}$/.test(query) && (!contacts[query] || !!contacts[query].hidden);

  async function add(e?: FormEvent) {
    e?.preventDefault();
    if (!canAdd) {
      if (list[0]) {
        void messenger.open(list[0].username);
        setQ('');
      }
      return;
    }
    setAdding(true);
    setError(null);
    try {
      const c = await messenger.addContact(query);
      setQ('');
      await messenger.open(c.username);
    } catch (err) {
      setError(err instanceof ApiError ? `err.${err.code}` : 'err.network');
    } finally {
      setAdding(false);
    }
  }

  return (
    <aside className="sidebar" aria-label={t('nav.chats')}>
      <header className="side-head">
        <div className="brand small">
          <Logo size={32} />
          <span className="brand-name">DoomMsg</span>
        </div>
        <button className="icon-btn" onClick={onSettings} aria-label={t('nav.settings')} title={t('nav.settings')}>
          <IconSettings />
        </button>
      </header>

      <form className="search" onSubmit={add} role="search">
        <IconSearch size={18} />
        <input
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setError(null);
          }}
          placeholder={t('nav.search')}
          aria-label={t('nav.search')}
          autoCapitalize="none"
          spellCheck={false}
        />
      </form>

      {conn !== 'online' && (
        <div className={`conn-banner ${conn}`} role="status">
          <span className="pulse" aria-hidden="true" />
          {conn === 'connecting' ? t('conn.connecting') : t('conn.offline')}
        </div>
      )}

      <div className="chat-list" role="list">
        {canAdd && (
          <button className="chat-item add" onClick={() => void add()} disabled={adding}>
            <span className="add-icon">
              <IconPlus />
            </span>
            <span className="chat-main">
              <span className="chat-name">{t('nav.startChat', { name: query })}</span>
              {error && <span className="chat-preview error">{t(error)}</span>}
            </span>
          </button>
        )}

        {list.map((c) => (
          <ChatItem
            key={c.username}
            c={c}
            active={active === c.username}
            typing={(typing[c.username] ?? 0) > Date.now()}
            lang={lang}
            t={t}
          />
        ))}

        {!list.length && !canAdd && (
          <div className="empty-list">
            <IconShield size={36} />
            <p className="empty-title">{query ? t('nav.noResults') : t('chats.empty')}</p>
            {!query && <p className="empty-hint">{t('chats.emptyHint')}</p>}
          </div>
        )}
      </div>
    </aside>
  );
}

function ChatItem({
  c,
  active,
  typing,
  lang,
  t,
}: {
  c: Contact;
  active: boolean;
  typing: boolean;
  lang: 'en' | 'fa';
  t: (k: string, p?: Record<string, string | number>) => string;
}) {
  const name = c.nickname || c.username;
  return (
    <button
      role="listitem"
      className={`chat-item ${active ? 'active' : ''}`}
      onClick={() => void messenger.open(c.username)}
      aria-current={active ? 'true' : undefined}
    >
      <Avatar name={name} hue={c.hue} />
      <span className="chat-main">
        <span className="chat-top">
          <span className="chat-name">
            <bdi>{name}</bdi>
            {c.verified && <IconShield size={14} className="verified-icon" aria-label={t('conv.verified')} />}
            {c.timer > 0 && <IconTimer size={14} className="muted-icon" />}
          </span>
          <span className="chat-time">{formatShort(lang, c.lastTs)}</span>
        </span>
        <span className="chat-bottom">
          <span className={`chat-preview ${typing ? 'typing' : ''}`}>
            {typing ? t('conv.typing') : <bdi>{c.lastPreview ?? `@${c.username}`}</bdi>}
          </span>
          {c.unread > 0 && <span className="badge">{new Intl.NumberFormat(lang === 'fa' ? 'fa-IR' : 'en-US').format(c.unread)}</span>}
        </span>
      </span>
    </button>
  );
}
