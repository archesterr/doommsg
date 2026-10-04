import { useCallback } from 'react';
import { useApp } from '../state/store';
import type { Lang } from '../state/types';
import { en, type MessageKey } from './en';
import { fa } from './fa';

const dicts: Record<Lang, Record<MessageKey, string>> = { en, fa };

export type { MessageKey };
export type Params = Record<string, string | number>;

export const dirOf = (lang: Lang): 'rtl' | 'ltr' => (lang === 'fa' ? 'rtl' : 'ltr');
export const localeOf = (lang: Lang): string => (lang === 'fa' ? 'fa-IR' : 'en-US');

export function isKey(k: string): k is MessageKey {
  return k in en;
}

export function translate(lang: Lang, key: string, params?: Params): string {
  const s: string = isKey(key) ? dicts[lang][key] : key;
  if (!params) return s;
  const nf = new Intl.NumberFormat(localeOf(lang), { useGrouping: false });
  return s.replace(/\{(\w+)\}/g, (_, p: string) => {
    const v = params[p];
    if (v === undefined) return `{${p}}`;
    return typeof v === 'number' ? nf.format(v) : v;
  });
}

/** Human label for a disappearing-message timer in seconds. */
export function timerLabel(lang: Lang, sec: number): string {
  if (!sec) return translate(lang, 'timer.off');
  const unit = (key: 'timer.w' | 'timer.d' | 'timer.h', n: number) =>
    translate(lang, n === 1 ? `${key}1` : key, { n });
  if (sec % 604800 === 0) return unit('timer.w', sec / 604800);
  if (sec % 86400 === 0) return unit('timer.d', sec / 86400);
  if (sec % 3600 === 0) return unit('timer.h', sec / 3600);
  return translate(lang, 'timer.m', { n: Math.max(1, Math.round(sec / 60)) });
}

export function useT() {
  const lang = useApp((s) => s.settings.lang);
  return useCallback((key: string, params?: Params) => translate(lang, key, params), [lang]);
}

export function useLang(): Lang {
  return useApp((s) => s.settings.lang);
}

export function formatTime(lang: Lang, ts: number): string {
  return new Intl.DateTimeFormat(localeOf(lang), { hour: '2-digit', minute: '2-digit' }).format(ts);
}

export function formatDay(lang: Lang, ts: number): string {
  const d = new Date(ts);
  const now = new Date();
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((startOf(now) - startOf(d)) / 86400000);
  if (diff === 0) return translate(lang, 'conv.today');
  if (diff === 1) return translate(lang, 'conv.yesterday');
  // fa-IR renders the Solar Hijri calendar with Persian digits.
  return new Intl.DateTimeFormat(localeOf(lang), {
    weekday: diff < 7 ? 'long' : undefined,
    day: 'numeric',
    month: 'long',
    year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric',
  }).format(d);
}

export function formatShort(lang: Lang, ts: number): string {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return formatTime(lang, ts);
  const days = (now.getTime() - ts) / 86400000;
  return new Intl.DateTimeFormat(localeOf(lang), days < 6 ? { weekday: 'short' } : { day: 'numeric', month: 'short' }).format(d);
}

export function formatDuration(lang: Lang, sec: number): string {
  const nf = new Intl.NumberFormat(localeOf(lang), { minimumIntegerDigits: 2, useGrouping: false });
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return (h ? `${nf.format(h)}:` : '') + `${nf.format(m)}:${nf.format(s)}`;
}

export function localDigits(lang: Lang, s: string): string {
  if (lang !== 'fa') return s;
  return s.replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);
}
