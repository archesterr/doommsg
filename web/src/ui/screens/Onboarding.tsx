import { useEffect, useState, type FormEvent } from 'react';
import { useT } from '../../i18n';
import { ApiError, type ServerInfo } from '../../net/api';
import { messenger } from '../../state/messenger';
import { useApp } from '../../state/store';
import { Logo, Segmented } from '../components/Common';
import { IconLock, IconShield, IconVideo } from '../icons/Icons';

export function Onboarding() {
  const t = useT();
  const lang = useApp((s) => s.settings.lang);
  const [username, setUsername] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<ServerInfo | null>(null);

  useEffect(() => {
    messenger.api.info().then(setInfo, () => setError('err.network'));
  }, []);

  const valid = /^[a-z0-9_]{3,32}$/.test(username);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      await messenger.register(username, code.trim());
    } catch (err) {
      setError(err instanceof ApiError ? `err.${err.code}` : 'err.network');
      setBusy(false);
    }
  }

  return (
    <main className="onboarding">
      <div className="onb-glow" aria-hidden="true" />
      <div className="onb-lang">
        <Segmented
          label={t('set.language')}
          value={lang}
          options={[
            { value: 'en', label: 'English' },
            { value: 'fa', label: 'فارسی' },
          ]}
          onChange={(v) => void messenger.updateSettings({ lang: v })}
        />
      </div>

      <section className="onb-hero">
        <div className="brand">
          <Logo size={56} />
          <span className="brand-name">DoomMsg</span>
        </div>
        <h1>{t('onb.title')}</h1>
        <p className="lead">{t('onb.subtitle')}</p>
        <ul className="features">
          <li>
            <span className="feat-icon">
              <IconLock />
            </span>
            <div>
              <strong>{t('onb.f1.title')}</strong>
              <span>{t('onb.f1.body')}</span>
            </div>
          </li>
          <li>
            <span className="feat-icon">
              <IconVideo />
            </span>
            <div>
              <strong>{t('onb.f2.title')}</strong>
              <span>{t('onb.f2.body')}</span>
            </div>
          </li>
          <li>
            <span className="feat-icon">
              <IconShield />
            </span>
            <div>
              <strong>{t('onb.f3.title')}</strong>
              <span>{t('onb.f3.body')}</span>
            </div>
          </li>
        </ul>
      </section>

      <form className="onb-card" onSubmit={submit} noValidate>
        <label className="field">
          <span className="field-label">{t('onb.username')}</span>
          <div className="input-wrap at">
            <span className="at-sign" aria-hidden="true">
              @
            </span>
            <input
              dir="ltr"
              autoFocus
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={32}
              value={username}
              onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ''))}
              aria-describedby="uhint"
              aria-invalid={username.length > 0 && !valid}
            />
          </div>
          <span id="uhint" className="field-hint">
            {t('onb.usernameHint')}
          </span>
        </label>

        {info?.registrationRequired && (
          <label className="field">
            <span className="field-label">{t('onb.code')}</span>
            <div className="input-wrap">
              <input dir="ltr" autoComplete="off" spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} />
            </div>
            <span className="field-hint">{t('onb.codeHint')}</span>
          </label>
        )}

        {error && (
          <p className="form-error" role="alert">
            {t(error)}
          </p>
        )}

        <button className="btn primary block" disabled={!valid || busy} type="submit">
          {busy ? (
            <>
              <span className="spinner" aria-hidden="true" /> {t('onb.creating')}
            </>
          ) : (
            t('onb.create')
          )}
        </button>
        <p className="onb-note">{t('onb.note')}</p>
      </form>
    </main>
  );
}
