// REST client. The session token lives in memory only; on every app start
// (or expiry) the client re-authenticates by signing a fresh server
// challenge with its identity key. No password, no persisted token.

import { b64, unb64, unb64n } from '../crypto/bytes';
import { LABEL, sign, type Identity, type PublicIdentity } from '../crypto/protocol';
import type { PreKeyBundle } from '../crypto/x3dh';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(`${status} ${code}`);
  }
}

export interface ServerInfo {
  name: string;
  version: string;
  registrationRequired: boolean;
  turn: boolean;
}

export interface IceConfig {
  iceServers: RTCIceServer[];
  expiresAt: number;
}

const BASE = '/api/v1';

export class Api {
  private token: string | null = null;
  private loginInFlight: Promise<string> | null = null;

  constructor(
    private username: () => string | null,
    private identity: () => Promise<Identity>,
  ) {}

  get authToken(): string | null {
    return this.token;
  }

  private async raw(method: string, path: string, body?: unknown, token?: string | null): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    return fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    });
  }

  private async json<T>(res: Response): Promise<T> {
    if (!res.ok) {
      let code = 'error';
      try {
        code = ((await res.json()) as { error?: string }).error ?? code;
      } catch {
        /* non-JSON error */
      }
      throw new ApiError(res.status, code);
    }
    if (res.status === 204 || res.status === 201) return undefined as T;
    return (await res.json()) as T;
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    let token = this.token ?? (await this.login());
    let res = await this.raw(method, path, body, token);
    if (res.status === 401) {
      this.token = null;
      token = await this.login();
      res = await this.raw(method, path, body, token);
    }
    return this.json<T>(res);
  }

  info(): Promise<ServerInfo> {
    return this.raw('GET', '/info').then((r) => this.json<ServerInfo>(r));
  }

  register(req: unknown): Promise<void> {
    return this.raw('POST', '/register', req).then((r) => this.json<void>(r));
  }

  /** Challenge-response login with the identity signing key. */
  login(): Promise<string> {
    this.loginInFlight ??= (async () => {
      try {
        const username = this.username();
        if (!username) throw new ApiError(401, 'no_account');
        const { challenge } = await this.json<{ challenge: string }>(
          await this.raw('POST', '/auth/challenge', { username }),
        );
        const id = await this.identity();
        const c = unb64n(challenge, 32, 'challenge');
        const { token } = await this.json<{ token: string }>(
          await this.raw('POST', '/auth/verify', {
            username,
            challenge,
            signature: b64(sign(id.sig.priv, LABEL.auth, c)),
          }),
        );
        this.token = token;
        return token;
      } finally {
        this.loginInFlight = null;
      }
    })();
    return this.loginInFlight;
  }

  async logout(): Promise<void> {
    if (!this.token) return;
    await this.raw('POST', '/auth/logout', undefined, this.token).catch(() => undefined);
    this.token = null;
  }

  async identityOf(username: string): Promise<PublicIdentity & { dhKeySig: Uint8Array }> {
    const r = await this.call<{ sigKey: string; dhKey: string; dhKeySig: string }>(
      'GET',
      `/users/${encodeURIComponent(username)}`,
    );
    return {
      sigKey: unb64n(r.sigKey, 32, 'sigKey'),
      dhKey: unb64n(r.dhKey, 32, 'dhKey'),
      dhKeySig: unb64n(r.dhKeySig, 64, 'dhKeySig'),
    };
  }

  async bundle(username: string): Promise<PreKeyBundle> {
    const r = await this.call<{
      sigKey: string;
      dhKey: string;
      dhKeySig: string;
      signedPreKey: { keyId: number; pub: string; sig: string };
      oneTimePreKey?: { keyId: number; pub: string };
    }>('POST', `/users/${encodeURIComponent(username)}/bundle`);
    return {
      sigKey: unb64n(r.sigKey, 32, 'sigKey'),
      dhKey: unb64n(r.dhKey, 32, 'dhKey'),
      dhKeySig: unb64n(r.dhKeySig, 64, 'dhKeySig'),
      signedPreKey: {
        keyId: r.signedPreKey.keyId,
        pub: unb64n(r.signedPreKey.pub, 32, 'spk'),
        sig: unb64(r.signedPreKey.sig),
      },
      oneTimePreKey: r.oneTimePreKey
        ? { keyId: r.oneTimePreKey.keyId, pub: unb64n(r.oneTimePreKey.pub, 32, 'opk') }
        : undefined,
    };
  }

  keyStatus(): Promise<{ oneTimePreKeys: number; max: number }> {
    return this.call('GET', '/keys');
  }

  putSignedPreKey(spk: { keyId: number; pub: string; sig: string }): Promise<void> {
    return this.call('PUT', '/keys/signed', spk);
  }

  addOneTimePreKeys(keys: { keyId: number; pub: string }[]): Promise<void> {
    return this.call('POST', '/keys/one-time', { keys });
  }

  turn(): Promise<IceConfig> {
    return this.call('GET', '/turn');
  }

  deleteAccount(): Promise<void> {
    return this.call('DELETE', '/account');
  }
}
