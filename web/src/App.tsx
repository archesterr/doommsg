import { useEffect, useState } from 'react';
import { calls } from './calls/callManager';
import { dirOf, useT } from './i18n';
import { useApp } from './state/store';
import { Logo, Toaster } from './ui/components/Common';
import { CallScreen } from './ui/screens/CallScreen';
import { ContactInfo } from './ui/screens/ContactInfo';
import { Conversation, EmptyConversation } from './ui/screens/Conversation';
import { Onboarding } from './ui/screens/Onboarding';
import { Settings } from './ui/screens/Settings';
import { Sidebar } from './ui/screens/Sidebar';

// Keep the call manager alive (it registers the signalling handler).
void calls;

function useDocumentSettings() {
  const { lang, theme } = useApp((s) => s.settings);
  useEffect(() => {
    const root = document.documentElement;
    root.lang = lang;
    root.dir = dirOf(lang);
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => {
      const resolved = theme === 'system' ? (mq.matches ? 'dark' : 'light') : theme;
      root.dataset.theme = resolved;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', resolved === 'dark' ? '#0c0a12' : '#f7f3ef');
    };
    apply();
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [lang, theme]);
}

export function App() {
  useDocumentSettings();
  const phase = useApp((s) => s.phase);
  const active = useApp((s) => s.active);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(false);

  useEffect(() => setInfoOpen(false), [active]);

  if (phase === 'loading') {
    return (
      <div className="splash">
        <Logo size={64} />
      </div>
    );
  }
  if (phase === 'unsupported') return <Notice kind="unsupported" />;
  if (phase === 'elsewhere') return <Notice kind="elsewhere" />;
  if (phase === 'onboarding') {
    return (
      <>
        <Onboarding />
        <Toaster />
      </>
    );
  }

  return (
    <div className={`app ${active ? 'has-active' : ''} ${infoOpen ? 'has-info' : ''}`}>
      <Sidebar onSettings={() => setSettingsOpen(true)} />
      <main className="main">
        {active ? <Conversation peer={active} onInfo={() => setInfoOpen((v) => !v)} /> : <EmptyConversation />}
      </main>
      {active && infoOpen && <ContactInfo peer={active} onClose={() => setInfoOpen(false)} />}
      <Settings open={settingsOpen} onClose={() => setSettingsOpen(false)} />
      <CallScreen />
      <Toaster />
    </div>
  );
}

function Notice({ kind }: { kind: 'unsupported' | 'elsewhere' }) {
  const t = useT();
  return (
    <main className="notice">
      <Logo size={64} />
      <h1>{t(`${kind}.title`)}</h1>
      <p>{t(`${kind}.body`)}</p>
      {kind === 'elsewhere' && (
        <button
          className="btn primary"
          onClick={() => {
            sessionStorage.setItem('doommsg.steal', '1');
            location.reload();
          }}
        >
          {t('elsewhere.useHere')}
        </button>
      )}
    </main>
  );
}

