import { useEffect, useState } from 'react';
import { b64 } from '../../crypto/bytes';
import { sha256 } from '../../crypto/protocol';
import { useT } from '../../i18n';
import { messenger } from '../../state/messenger';
import { toast, useApp } from '../../state/store';
import { localKeyStore } from '../../storage/keystore';
import { Confirm, Modal, Segmented, Switch } from '../components/Common';
import { IconBell, IconCopy } from '../icons/Icons';

export function Settings({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT();
  const settings = useApp((s) => s.settings);
  const username = useApp((s) => s.account?.username ?? '');
  const [fingerprint, setFingerprint] = useState('');
  const [confirm, setConfirm] = useState<'wipe' | 'delete' | null>(null);
  const [perm, setPerm] = useState(typeof Notification === 'undefined' ? 'denied' : Notification.permission);

  useEffect(() => {
    if (!open) return;
    void localKeyStore.identity().then((id) => {
      const h = b64(sha256(new Uint8Array([...id.sig.pub, ...id.dh.pub]))).slice(0, 32);
      setFingerprint(h.match(/.{4}/g)!.join(' '));
    });
  }, [open]);

  const set = messenger.updateSettings.bind(messenger);

  return (
    <Modal open={open} onClose={onClose} title={t('set.title')} className="settings">
      <div className="settings-scroll">
        <section className="card">
          <h4>{t('set.account')}</h4>
          <div className="row">
            <span className="row-text">
              <span className="row-label">{t('set.username')}</span>
              <span className="row-hint">{t('set.share')}</span>
            </span>
            <button className="handle-btn" dir="ltr" onClick={() => void navigator.clipboard?.writeText(`@${username}`).then(() => toast('conv.copied'))}>
              @{username} <IconCopy size={14} />
            </button>
          </div>
        </section>

        <section className="card">
          <h4>{t('set.appearance')}</h4>
          <div className="row">
            <span className="row-label">{t('set.language')}</span>
            <Segmented
              label={t('set.language')}
              value={settings.lang}
              options={[
                { value: 'en', label: 'English' },
                { value: 'fa', label: 'فارسی' },
              ]}
              onChange={(lang) => void set({ lang })}
            />
          </div>
          <div className="row">
            <span className="row-label">{t('set.theme')}</span>
            <Segmented
              label={t('set.theme')}
              value={settings.theme}
              options={[
                { value: 'system', label: t('theme.system') },
                { value: 'dark', label: t('theme.dark') },
                { value: 'light', label: t('theme.light') },
              ]}
              onChange={(theme) => void set({ theme })}
            />
          </div>
          <Switch label={t('set.enterToSend')} checked={settings.enterToSend} onChange={(v) => void set({ enterToSend: v })} />
        </section>

        <section className="card">
          <h4>{t('set.privacy')}</h4>
          <Switch label={t('set.readReceipts')} hint={t('set.readReceiptsHint')} checked={settings.readReceipts} onChange={(v) => void set({ readReceipts: v })} />
          <Switch label={t('set.typing')} checked={settings.typingIndicators} onChange={(v) => void set({ typingIndicators: v })} />
          <Switch label={t('set.relayCalls')} hint={t('set.relayCallsHint')} checked={settings.relayCalls} onChange={(v) => void set({ relayCalls: v })} />
          <Switch label={t('set.notifications')} hint={t('set.notificationsHint')} checked={settings.notifications} onChange={(v) => void set({ notifications: v })} />
          {settings.notifications && perm === 'default' && (
            <button className="btn small ghost" onClick={() => void Notification.requestPermission().then(setPerm)}>
              <IconBell size={16} /> {t('notif.enable')}
            </button>
          )}
        </section>

        <section className="card">
          <h4>{t('set.security')}</h4>
          <div className="row column">
            <span className="row-label">{t('set.fingerprint')}</span>
            <code className="fingerprint" dir="ltr">
              {fingerprint}
            </code>
          </div>
          <p className="muted small">{t('set.aboutText')}</p>
        </section>

        <section className="card danger-zone">
          <h4>{t('set.danger')}</h4>
          <button className="list-btn danger" onClick={() => setConfirm('wipe')}>
            {t('set.wipe')}
          </button>
          <button className="list-btn danger" onClick={() => setConfirm('delete')}>
            {t('set.deleteAccount')}
          </button>
        </section>
        <p className="version">DoomMsg v0.1.0</p>
      </div>
      <Confirm
        open={confirm !== null}
        danger
        text={confirm === 'delete' ? t('set.deleteConfirm') : t('set.wipeConfirm')}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          const action = confirm;
          setConfirm(null);
          if (action === 'delete') void messenger.deleteAccount().catch(() => toast('err.generic', 'error'));
          else void messenger.wipeDevice();
        }}
      />
    </Modal>
  );
}
