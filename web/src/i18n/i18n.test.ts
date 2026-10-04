import { describe, expect, it } from 'vitest';
import { en } from './en';
import { fa } from './fa';
import { timerLabel, translate } from './index';

describe('i18n', () => {
  it('has a Persian translation for every English key and no extras', () => {
    expect(Object.keys(fa).sort()).toEqual(Object.keys(en).sort());
  });

  it('keeps placeholders consistent across languages', () => {
    const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort();
    for (const k of Object.keys(en) as (keyof typeof en)[]) {
      expect(ph(fa[k]), k).toEqual(ph(en[k]));
    }
  });

  it('formats numbers with Persian digits', () => {
    expect(translate('fa', 'timer.m', { n: 5 })).toBe('۵ دقیقه');
    expect(translate('en', 'timer.m', { n: 5 })).toBe('5 min');
    expect(timerLabel('en', 3600)).toBe('1 hour');
    expect(timerLabel('fa', 604800)).toBe('۱ هفته');
    expect(timerLabel('en', 0)).toBe('Off');
  });
});
