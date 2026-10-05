import { expect, test, type Browser, type Page } from '@playwright/test';

const shots = process.env.E2E_SCREENSHOTS;

// Any uncaught error or CSP violation fails the suite.
const problems: string[] = [];
test.afterEach(() => {
  expect(problems, 'page errors / CSP violations').toEqual([]);
  problems.length = 0;
});

async function user(browser: Browser, name: string, lang?: 'fa'): Promise<Page> {
  const ctx = await browser.newContext({
    permissions: ['camera', 'microphone'],
    locale: lang === 'fa' ? 'fa-IR' : 'en-US',
    viewport: { width: 1280, height: 800 },
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`[${name}] ${e.message}`));
  page.on('console', (m) => {
    if (/Content Security Policy|Trusted Type/i.test(m.text())) problems.push(`[${name}] ${m.text()}`);
  });
  await page.goto('/');
  await page.locator('.onb-card input').first().fill(name);
  if (shots && name === 'alice') await page.screenshot({ path: `${shots}/onboarding.png` });
  await page.locator('.onb-card button[type=submit]').click();
  await expect(page.locator('.sidebar')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('.conn-banner')).toHaveCount(0, { timeout: 15_000 });
  return page;
}

test('two users exchange end-to-end encrypted messages and make a video call', async ({ browser }) => {
  const alice = await user(browser, 'alice');
  const bob = await user(browser, 'bob', 'fa');

  // Bob's browser locale is Persian: the UI must be RTL.
  await expect(bob.locator('html')).toHaveAttribute('dir', 'rtl');

  // Alice starts a chat with Bob and sends the first (prekey) message.
  await alice.locator('.search input').fill('bob');
  await alice.locator('.search input').press('Enter');
  await expect(alice.locator('.conv-name')).toContainText('bob');
  await alice.locator('.composer textarea').fill('Hello Bob 👋 — this is end-to-end encrypted');
  await alice.locator('.composer textarea').press('Enter');
  await expect(alice.locator('.msg-row.out .body').last()).toHaveText('Hello Bob 👋 — this is end-to-end encrypted');

  // Bob receives it from an unknown sender (TOFU against the directory).
  await expect(bob.locator('.chat-item', { hasText: 'alice' })).toBeVisible({ timeout: 15_000 });
  await bob.locator('.chat-item', { hasText: 'alice' }).click();
  await expect(bob.locator('.msg-row.in .body').last()).toHaveText('Hello Bob 👋 — this is end-to-end encrypted');

  // Alice sees the read receipt once Bob has the chat open.
  await expect(alice.locator('.msg-row.out .st.read').last()).toBeVisible({ timeout: 15_000 });

  // Bob replies in Persian.
  await bob.locator('.composer textarea').fill('سلام آلیس! پیامت رسید.');
  await bob.locator('.composer textarea').press('Enter');
  await expect(alice.locator('.msg-row.in .body').last()).toHaveText('سلام آلیس! پیامت رسید.', { timeout: 15_000 });

  // Several more messages in both directions exercise the ratchet.
  for (let i = 0; i < 3; i++) {
    await alice.locator('.composer textarea').fill(`ping ${i}`);
    await alice.locator('.composer textarea').press('Enter');
    await expect(bob.locator('.msg-row.in .body').last()).toHaveText(`ping ${i}`, { timeout: 15_000 });
    await bob.locator('.composer textarea').fill(`pong ${i}`);
    await bob.locator('.composer textarea').press('Enter');
    await expect(alice.locator('.msg-row.in .body').last()).toHaveText(`pong ${i}`, { timeout: 15_000 });
  }

  // Safety numbers match on both sides.
  await alice.locator('.conv-actions button').nth(2).click();
  await bob.locator('.conv-actions button').nth(2).click();
  await expect(alice.locator('.safety-grid span:not(.skeleton)')).toHaveCount(12);
  await expect(bob.locator('.safety-grid span:not(.skeleton)')).toHaveCount(12);
  const sa = await alice.locator('.safety-grid').innerText();
  const sb = await bob.locator('.safety-grid').innerText();
  const digits = (s: string) => s.replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d))).replace(/\s+/g, '');
  expect(digits(sa)).toBe(digits(sb));
  expect(digits(sa)).toMatch(/^\d{60}$/);
  if (shots) {
    await alice.screenshot({ path: `${shots}/chat-en.png` });
    await bob.screenshot({ path: `${shots}/chat-fa.png` });
  }
  await alice.locator('.panel-head button').click();
  await bob.locator('.panel-head button').click();

  // Video call: signalling travels through the encrypted channel.
  await alice.locator('.conv-actions button').nth(1).click();
  await expect(bob.locator('.call-btn.accept')).toBeVisible({ timeout: 15_000 });
  if (shots) await bob.screenshot({ path: `${shots}/call-incoming.png` });
  await bob.locator('.call-btn.accept').click();
  // Connected: the call timer is running on both sides.
  const timer = /[0-9۰-۹]{2}:[0-9۰-۹]{2}/;
  await expect(alice.locator('.call-screen')).toContainText(timer, { timeout: 30_000 });
  await expect(bob.locator('.call-screen')).toContainText(timer, { timeout: 30_000 });
  await expect(alice.locator('.call-screen.has-video')).toBeVisible({ timeout: 15_000 });
  if (shots) await alice.screenshot({ path: `${shots}/call-active.png` });
  await alice.locator('.call-btn.decline').click();
  await expect(alice.locator('.call-screen')).toHaveCount(0);
  await expect(bob.locator('.call-screen')).toHaveCount(0, { timeout: 15_000 });
  await expect(alice.locator('.call-msg')).toHaveCount(1);
  await expect(bob.locator('.call-msg')).toHaveCount(1);

  // Messages survive a reload (encrypted local storage + session restore).
  await bob.reload();
  await bob.locator('.chat-item', { hasText: 'alice' }).click();
  await expect(bob.locator('.msg-row.in .body').last()).toHaveText('ping 2');
  await alice.locator('.composer textarea').fill('after reload');
  await alice.locator('.composer textarea').press('Enter');
  await expect(bob.locator('.msg-row.in .body').last()).toHaveText('after reload', { timeout: 15_000 });
});

test('a second tab is locked out to protect ratchet state', async ({ browser }) => {
  const page = await user(browser, 'carol');
  const second = await page.context().newPage();
  await second.goto('/');
  await expect(second.locator('.notice')).toBeVisible();
  await second.locator('.notice button').click();
  await expect(second.locator('.sidebar')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('.notice')).toBeVisible({ timeout: 15_000 });
});
