import '@fontsource-variable/vazirmatn';
import './styles/app.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { messenger } from './state/messenger';
import { useApp } from './state/store';

function supported(): boolean {
  return (
    window.isSecureContext &&
    typeof crypto?.subtle !== 'undefined' &&
    typeof indexedDB !== 'undefined' &&
    typeof WebSocket !== 'undefined'
  );
}

/**
 * Only one tab may drive the ratchet sessions at a time; two tabs sharing
 * IndexedDB would race and corrupt them. A Web Lock enforces that.
 */
function acquireTabLock(steal: boolean): Promise<boolean> {
  if (!navigator.locks) return Promise.resolve(true);
  return new Promise((resolve) => {
    navigator.locks
      .request('doommsg-active-tab', steal ? { steal: true } : { ifAvailable: true }, async (lock) => {
        if (!lock) {
          resolve(false);
          return;
        }
        resolve(true);
        await new Promise(() => {}); // hold for the lifetime of the tab
      })
      .catch(() => {
        // Another tab stole the lock ("Use here").
        messenger.stop();
        useApp.setState({ phase: 'elsewhere' });
      });
  });
}

async function boot() {
  if (!supported()) {
    useApp.setState({ phase: 'unsupported' });
    return;
  }
  const steal = sessionStorage.getItem('doommsg.steal') === '1';
  sessionStorage.removeItem('doommsg.steal');
  if (!(await acquireTabLock(steal))) {
    useApp.setState({ phase: 'elsewhere' });
    return;
  }
  // Ask the browser not to evict our keys under storage pressure.
  void navigator.storage?.persist?.().catch(() => false);
  await messenger.boot();
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

void boot().catch((e) => {
  console.error('boot failed', e);
  useApp.setState({ phase: 'unsupported' });
});
