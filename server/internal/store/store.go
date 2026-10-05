// Package store persists the (deliberately small) server state in SQLite.
//
// The server is a zero-knowledge relay: it stores public keys, hashed
// session tokens and opaque ciphertext envelopes that are deleted as soon
// as the recipient acknowledges them. It never sees plaintext or private
// keys.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO needed
)

var (
	ErrNotFound   = errors.New("not found")
	ErrExists     = errors.New("already exists")
	ErrMailboxFul = errors.New("recipient mailbox full")
)

// MaxOneTimePreKeys caps how many one-time prekeys a user may store.
const MaxOneTimePreKeys = 500

// senderShare limits one sender to 1/senderShare of a recipient's mailbox
// (by count and by bytes), so a single account cannot fill it and lock
// every other sender out.
const senderShare = 10

// connMaxIdleTime closes idle file-database connections. It is a variable
// so tests can shorten it.
var connMaxIdleTime = 5 * time.Minute

type Store struct {
	db *sql.DB
}

type User struct {
	ID        int64
	Username  string
	SigKey    []byte // Ed25519 identity signing key
	DHKey     []byte // X25519 identity DH key
	DHKeySig  []byte // Ed25519 signature over DHKey (binds the two keys)
	CreatedAt time.Time
}

type SignedPreKey struct {
	KeyID int64
	Pub   []byte
	Sig   []byte
}

type OneTimePreKey struct {
	KeyID int64
	Pub   []byte
}

type Bundle struct {
	User         User
	SignedPreKey SignedPreKey
	OneTime      *OneTimePreKey // nil when exhausted
}

type Envelope struct {
	ID        int64
	Sender    string
	Payload   []byte
	CreatedAt time.Time
}

type Session struct {
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

// MailboxLimits caps what may be queued for one recipient.
type MailboxLimits struct {
	Max      int   // envelopes
	MaxBytes int64 // total payload bytes
}

// Open opens (and migrates) the database at path. Use ":memory:" in tests.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "secure_delete(ON)") // overwrite deleted ciphertext on disk
	q.Add("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" || strings.Contains(path, "mode=memory") {
		// Every connection to :memory: is a distinct database, so the only
		// one must never be closed: a replacement would start out empty.
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(8)
		db.SetConnMaxIdleTime(connMaxIdleTime)
	}

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

var migrations = []string{
	`CREATE TABLE users (
		id         INTEGER PRIMARY KEY,
		username   TEXT NOT NULL UNIQUE,
		sig_key    BLOB NOT NULL,
		dh_key     BLOB NOT NULL,
		dh_key_sig BLOB NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE signed_prekeys (
		user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		key_id     INTEGER NOT NULL,
		pub        BLOB NOT NULL,
		sig        BLOB NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE one_time_prekeys (
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		key_id  INTEGER NOT NULL,
		pub     BLOB NOT NULL,
		PRIMARY KEY (user_id, key_id)
	) WITHOUT ROWID;
	CREATE TABLE sessions (
		token_hash BLOB PRIMARY KEY,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at INTEGER NOT NULL
	) WITHOUT ROWID;
	CREATE INDEX sessions_user ON sessions(user_id);
	CREATE INDEX sessions_expiry ON sessions(expires_at);
	CREATE TABLE challenges (
		challenge  BLOB PRIMARY KEY,
		username   TEXT NOT NULL,
		expires_at INTEGER NOT NULL
	) WITHOUT ROWID;
	CREATE TABLE mailbox (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		sender       TEXT NOT NULL,
		payload      BLOB NOT NULL,
		created_at   INTEGER NOT NULL,
		expires_at   INTEGER NOT NULL
	);
	CREATE INDEX mailbox_recipient ON mailbox(recipient_id, id);
	CREATE INDEX mailbox_expiry ON mailbox(expires_at);`,
	// Lets Enqueue add up a mailbox's usage, in total and per sender,
	// from the index alone.
	`CREATE INDEX mailbox_usage ON mailbox(recipient_id, sender, length(payload));`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser registers a user together with their initial prekeys.
func (s *Store) CreateUser(ctx context.Context, u User, spk SignedPreKey, otks []OneTimePreKey) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, sig_key, dh_key, dh_key_sig, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.Username, u.SigKey, u.DHKey, u.DHKeySig, now)
	if err != nil {
		if isUnique(err) {
			return 0, ErrExists
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO signed_prekeys (user_id, key_id, pub, sig, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, spk.KeyID, spk.Pub, spk.Sig, now); err != nil {
		return 0, err
	}
	if err := insertOTKs(ctx, tx, id, otks); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func insertOTKs(ctx context.Context, tx *sql.Tx, userID int64, otks []OneTimePreKey) error {
	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO one_time_prekeys (user_id, key_id, pub) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, k := range otks {
		if _, err := stmt.ExecContext(ctx, userID, k.KeyID, k.Pub); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UserByName(ctx context.Context, username string) (*User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, sig_key, dh_key, dh_key_sig, created_at FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.SigKey, &u.DHKey, &u.DHKeySig, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

// TakeBundle returns the prekey bundle of a user and atomically consumes
// one one-time prekey, so each one is handed out at most once.
func (s *Store) TakeBundle(ctx context.Context, username string) (*Bundle, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var b Bundle
	var created int64
	err = tx.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.sig_key, u.dh_key, u.dh_key_sig, u.created_at, s.key_id, s.pub, s.sig
		   FROM users u JOIN signed_prekeys s ON s.user_id = u.id
		  WHERE u.username = ?`, username).
		Scan(&b.User.ID, &b.User.Username, &b.User.SigKey, &b.User.DHKey, &b.User.DHKeySig, &created,
			&b.SignedPreKey.KeyID, &b.SignedPreKey.Pub, &b.SignedPreKey.Sig)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.User.CreatedAt = time.Unix(created, 0)

	var otk OneTimePreKey
	err = tx.QueryRowContext(ctx,
		`DELETE FROM one_time_prekeys
		  WHERE user_id = ? AND key_id = (SELECT MIN(key_id) FROM one_time_prekeys WHERE user_id = ?)
		 RETURNING key_id, pub`, b.User.ID, b.User.ID).Scan(&otk.KeyID, &otk.Pub)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Exhausted: X3DH still works without a one-time prekey.
	case err != nil:
		return nil, err
	default:
		b.OneTime = &otk
	}
	return &b, tx.Commit()
}

func (s *Store) SetSignedPreKey(ctx context.Context, userID int64, spk SignedPreKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO signed_prekeys (user_id, key_id, pub, sig, created_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET key_id = excluded.key_id, pub = excluded.pub,
		    sig = excluded.sig, created_at = excluded.created_at`,
		userID, spk.KeyID, spk.Pub, spk.Sig, time.Now().Unix())
	return err
}

// AddOneTimePreKeys stores more one-time prekeys, refusing to exceed
// MaxOneTimePreKeys in total.
func (s *Store) AddOneTimePreKeys(ctx context.Context, userID int64, otks []OneTimePreKey) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return err
	}
	if n+len(otks) > MaxOneTimePreKeys {
		return fmt.Errorf("too many one-time prekeys (have %d, max %d)", n, MaxOneTimePreKeys)
	}
	if err := insertOTKs(ctx, tx, userID, otks); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CountOneTimePreKeys(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM one_time_prekeys WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

func (s *Store) CreateChallenge(ctx context.Context, challenge []byte, username string, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (challenge, username, expires_at) VALUES (?, ?, ?)`,
		challenge, username, time.Now().Add(ttl).Unix())
	return err
}

// ConsumeChallenge deletes the challenge and reports whether it was valid
// for username and unexpired. Challenges are strictly single-use.
func (s *Store) ConsumeChallenge(ctx context.Context, challenge []byte, username string) (bool, error) {
	var owner string
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM challenges WHERE challenge = ? RETURNING username, expires_at`, challenge).
		Scan(&owner, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return owner == username && time.Now().Unix() < exp, nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, ttl time.Duration) (time.Time, error) {
	exp := time.Now().Add(ttl)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, userID, exp.Unix())
	return exp, err
}

// SessionUser resolves a hashed session token to its (unexpired) session.
func (s *Store) SessionUser(ctx context.Context, tokenHash []byte) (*Session, error) {
	var sess Session
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id
		  WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, time.Now().Unix()).
		Scan(&sess.UserID, &sess.Username, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = time.Unix(exp, 0)
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// mailboxUsage counts a recipient's queued envelopes and payload bytes;
// with senderUsage appended, only those of one sender. Both are answered
// from the mailbox_usage index.
const (
	mailboxUsage = `SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM mailbox WHERE recipient_id = ?`
	senderUsage  = ` AND sender = ?`
)

// Enqueue stores an envelope for later delivery and returns its id. It
// fails with ErrMailboxFul when the envelope would exceed lim, or the
// sender's share of it.
func (s *Store) Enqueue(ctx context.Context, recipientID int64, sender string, payload []byte, ttl time.Duration, lim MailboxLimits) (int64, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer tx.Rollback()
	var n, size, nSender, sizeSender int64
	if err := tx.QueryRowContext(ctx, mailboxUsage, recipientID).Scan(&n, &size); err != nil {
		return 0, time.Time{}, err
	}
	if err := tx.QueryRowContext(ctx, mailboxUsage+senderUsage, recipientID, sender).Scan(&nSender, &sizeSender); err != nil {
		return 0, time.Time{}, err
	}
	add := int64(len(payload))
	// A mailbox smaller than senderShare envelopes still takes one from
	// each sender.
	senderMax := max(int64(lim.Max)/senderShare, 1)
	if n >= int64(lim.Max) || size+add > lim.MaxBytes ||
		nSender >= senderMax || sizeSender+add > lim.MaxBytes/senderShare {
		return 0, time.Time{}, ErrMailboxFul
	}
	now := time.Now()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO mailbox (recipient_id, sender, payload, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		recipientID, sender, payload, now.UnixMilli(), now.Add(ttl).Unix())
	if err != nil {
		return 0, time.Time{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, time.Time{}, err
	}
	return id, now, tx.Commit()
}

// Pending lists queued envelopes for a recipient with id > after.
func (s *Store) Pending(ctx context.Context, recipientID, after int64, limit int) ([]Envelope, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, payload, created_at FROM mailbox
		  WHERE recipient_id = ? AND id > ? AND expires_at > ?
		  ORDER BY id LIMIT ?`, recipientID, after, time.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Envelope
	for rows.Next() {
		var e Envelope
		var ms int64
		if err := rows.Scan(&e.ID, &e.Sender, &e.Payload, &ms); err != nil {
			return nil, err
		}
		e.CreatedAt = time.UnixMilli(ms)
		out = append(out, e)
	}
	return out, rows.Err()
}

// LastEnvelope returns the id of the newest envelope queued for
// recipientID, or 0 when there is none. Ids only ever grow.
func (s *Store) LastEnvelope(ctx context.Context, recipientID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id), 0) FROM mailbox WHERE recipient_id = ?`, recipientID).Scan(&id)
	return id, err
}

// Ack deletes delivered envelopes. Only the recipient can delete them.
func (s *Store) Ack(ctx context.Context, recipientID int64, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `DELETE FROM mailbox WHERE id = ? AND recipient_id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, id, recipientID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Purge removes expired sessions, challenges and envelopes.
func (s *Store) Purge(ctx context.Context) (int64, error) {
	now := time.Now().Unix()
	var total int64
	for _, q := range []string{
		`DELETE FROM sessions WHERE expires_at <= ?`,
		`DELETE FROM challenges WHERE expires_at <= ?`,
		`DELETE FROM mailbox WHERE expires_at <= ?`,
	} {
		res, err := s.db.ExecContext(ctx, q, now)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
