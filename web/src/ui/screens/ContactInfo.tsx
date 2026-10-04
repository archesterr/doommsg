import { useEffect, useState } from 'react';
import { safetyNumber } from '../../crypto/safety';
import { localDigits, timerLabel, useLang, useT } from '../../i18n';
import { messenger } from '../../state/messenger';
import { toast, useApp } from '../../state/store';
import { localKeyStore } from '../../storage/keystore';
import { Avatar, Confirm } from '../components/Common';
import { IconBlock, IconClose, IconCopy, IconShield, IconShieldAlert, IconTrash } from '../icons/Icons';

const TIMERS = [0, 300, 3600, 8 * 3600, 86400, 7 * 86400];

export function ContactInfo({ peer, onClose }: { peer: string; onClose: () => void }) {
  const t = useT();
  const lang = useLang();
  const contact = useApp((s) => s.contacts[peer]);
  const me = useApp((s) => s.account?.username);
  const [number, setNumber] = useState<string[] | null>(null);
  const [nick, setNick] = useState(contact?.nickname ?? '');
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => setNick(contact?.nickname ?? ''), [contact?.nickname, peer]);

  useEffect(() => {
    if (!contact || !me) return;
    let alive = true;
    void localKeyStore.identity().then((id) => {
      // Iterated hashing takes a moment; let the panel paint first.
      setTimeout(() => {
        if (!alive) return;
        setNumber(
          safetyNumber(
            { username: me, identity: { sigKey: id.sig.pub, dhKey: id.dh.pub } },
            { username: contact.username, identity: contact.identity },
          ),
        );
      }, 0);
    });
    return () => {
      alive = false;
    };
  }, [contact, me]);

  if (!contact) return null;
  const name = contact.nickname || contact.username;

  return (
    <aside className="info-panel" aria-label={t('info.title')}>
      <header className="panel-head">
        <h2>{t('info.title')}</h2>
        <button className="icon-btn" onClick={onClose} aria-label={t('common.close')}>
          <IconClose />
        </button>
      </header>
      <div className="panel-scroll">
        <div className="profile">
          <Avatar name={name} hue={contact.hue} size={88} />
          <h3>
            <bdi>{name}</bdi>
          </h3>
          <span className="handle" dir="ltr">
            @{contact.username}
          </span>
          <span className={`pill ${contact.verified ? 'ok' : contact.identityChanged ? 'warn' : ''}`}>
            {contact.verified ? <IconShield size={14} /> : <IconShieldAlert size={14} />}
            {contact.verified ? t('conv.verified') : t('conv.unverified')}
          </span>
        </div>

        <section className="card">
          <form
            className="inline-form"
            onSubmit={(e) => {
              e.preventDefault();
              void messenger.renameContact(peer, nick);
            }}
          >
            <label className="field-label" htmlFor="nick">
              {t('info.nickname')}
            </label>
            <div className="input-row">
              <input id="nick" dir="auto" value={nick} maxLength={64} onChange={(e) => setNick(e.target.value)} placeholder={contact.username} />
              <button className="btn small" type="submit" disabled={nick === (contact.nickname ?? '')}>
                {t('info.save')}
              </button>
            </div>
          </form>
        </section>

        <section className="card">
          <h4>{t('info.safety')}</h4>
          <p className="muted small">{t('info.safetyHint', { name })}</p>
          <div className="safety-grid" dir="ltr" aria-live="polite">
            {number
              ? number.map((g, i) => <span key={i}>{localDigits(lang, g)}</span>)
              : Array.from({ length: 12 }, (_, i) => <span key={i} className="skeleton" />)}
          </div>
          <div className="btn-row">
            <button
              className="btn small ghost"
              disabled={!number}
              onClick={() => void navigator.clipboard?.writeText(number!.join(' ')).then(() => toast('conv.copied'))}
            >
              <IconCopy size={16} /> {t('info.copyNumber')}
            </button>
            <button className={`btn small ${contact.verified ? 'ghost' : 'primary'}`} onClick={() => void messenger.setVerified(peer, !contact.verified)}>
              <IconShield size={16} /> {contact.verified ? t('info.unmarkVerified') : t('info.markVerified')}
            </button>
          </div>
        </section>

        <section className="card">
          <h4>{t('info.timer')}</h4>
          <p className="muted small">{t('info.timerHint')}</p>
          <div className="chips" role="radiogroup" aria-label={t('info.timer')}>
            {TIMERS.map((s) => (
              <button
                key={s}
                role="radio"
                aria-checked={contact.timer === s}
                className={`chip ${contact.timer === s ? 'on' : ''}`}
                onClick={() => void messenger.setTimer(peer, s)}
              >
                {timerLabel(lang, s)}
              </button>
            ))}
          </div>
        </section>

        <section className="card actions">
          <button className="list-btn" onClick={() => void messenger.setBlocked(peer, !contact.blocked)}>
            <IconBlock size={18} /> {contact.blocked ? t('info.unblock') : t('info.block')}
          </button>
          <button className="list-btn danger" onClick={() => setConfirmDelete(true)}>
            <IconTrash size={18} /> {t('info.delete')}
          </button>
        </section>
      </div>
      <Confirm
        open={confirmDelete}
        danger
        text={t('info.deleteConfirm')}
        onCancel={() => setConfirmDelete(false)}
        onConfirm={() => {
          setConfirmDelete(false);
          onClose();
          void messenger.deleteChat(peer);
        }}
      />
    </aside>
  );
}
