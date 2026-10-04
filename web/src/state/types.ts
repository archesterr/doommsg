import type { PublicIdentity } from '../crypto/protocol';

export type Lang = 'en' | 'fa';
export type Theme = 'system' | 'dark' | 'light';

export interface Account {
  username: string;
  createdAt: number;
}

export interface Settings {
  lang: Lang;
  theme: Theme;
  /** Force calls through TURN so peers never learn each other's IP. */
  relayCalls: boolean;
  readReceipts: boolean;
  typingIndicators: boolean;
  notifications: boolean;
  enterToSend: boolean;
}

export const defaultSettings = (lang: Lang = 'en'): Settings => ({
  lang,
  theme: 'system',
  relayCalls: false,
  readReceipts: true,
  typingIndicators: true,
  notifications: true,
  enterToSend: true,
});

export interface Contact {
  username: string;
  nickname?: string;
  identity: PublicIdentity;
  verified: boolean;
  /** Set when the peer's identity key changed; cleared once acknowledged. */
  identityChanged?: number;
  /** Disappearing-message timer in seconds; 0 = off. */
  timer: number;
  lastTs: number;
  lastPreview?: string;
  unread: number;
  blocked?: boolean;
  /** Hue (0-359) for the generated avatar. */
  hue: number;
}

export type MessageStatus = 'pending' | 'sent' | 'delivered' | 'read' | 'failed';

export interface CallInfo {
  video: boolean;
  outcome: 'completed' | 'missed' | 'declined' | 'failed' | 'busy' | 'cancelled';
  durationSec?: number;
}

export interface ChatMessage {
  id: string;
  peer: string;
  dir: 'in' | 'out';
  kind: 'text' | 'system' | 'call';
  body: string;
  ts: number;
  status: MessageStatus;
  /** Epoch ms after which the message is deleted locally on both sides. */
  expiresAt?: number;
  /** Timer (seconds) in force when the message was sent. */
  timer?: number;
  call?: CallInfo;
  /** For system messages: an i18n key and params rendered at display time. */
  sys?: { key: string; params?: Record<string, string | number> };
  replyTo?: { id: string; body: string; dir: 'in' | 'out' };
}
