package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addUser(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	id, err := s.CreateUser(context.Background(),
		User{Username: name, SigKey: []byte{1}, DHKey: []byte{2}, DHKeySig: []byte{3}},
		SignedPreKey{KeyID: 1, Pub: []byte{4}, Sig: []byte{5}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEnqueueLimits(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	enqueue := func(rcpt int64, lim MailboxLimits, sender string, size int) (int64, error) {
		id, _, err := s.Enqueue(ctx, rcpt, sender, make([]byte, size), time.Hour, lim)
		return id, err
	}
	ok := func(id int64, err error) int64 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	full := func(_ int64, err error) {
		t.Helper()
		if !errors.Is(err, ErrMailboxFul) {
			t.Fatalf("got %v, want ErrMailboxFul", err)
		}
	}

	bob := addUser(t, s, "bob")
	lim := MailboxLimits{Max: 20, MaxBytes: 1000} // one sender: 2 envelopes, 100 bytes

	// Each sender is held to a tenth of the envelopes...
	first := ok(enqueue(bob, lim, "alice", 10))
	ok(enqueue(bob, lim, "alice", 10))
	full(enqueue(bob, lim, "alice", 10))
	// ...and of the bytes.
	ok(enqueue(bob, lim, "carol", 100))
	full(enqueue(bob, lim, "carol", 1))
	// Acked envelopes no longer count.
	if err := s.Ack(ctx, bob, []int64{first}); err != nil {
		t.Fatal(err)
	}
	ok(enqueue(bob, lim, "alice", 10))

	// The whole mailbox is capped by count...
	for i := range 17 {
		ok(enqueue(bob, lim, fmt.Sprint("s", i/2), 1))
	}
	full(enqueue(bob, lim, "dave", 1))

	// ...and by bytes, separately for every recipient.
	eve := addUser(t, s, "eve")
	lim = MailboxLimits{Max: 1000, MaxBytes: 1000}
	for i := range 10 {
		ok(enqueue(eve, lim, fmt.Sprint("s", i), 100))
	}
	full(enqueue(eve, lim, "dave", 1))

	// A mailbox smaller than senderShare envelopes still accepts one
	// envelope from each sender.
	frank := addUser(t, s, "frank")
	lim = MailboxLimits{Max: 3, MaxBytes: 1 << 20}
	ok(enqueue(frank, lim, "alice", 1))
	full(enqueue(frank, lim, "alice", 1))
	ok(enqueue(frank, lim, "carol", 1))
	ok(enqueue(frank, lim, "dave", 1))
	full(enqueue(frank, lim, "eve", 1))
}

// The usage queries Enqueue runs on every send must not visit table rows.
func TestMailboxUsageIsIndexOnly(t *testing.T) {
	s := openTest(t)
	for _, q := range []string{mailboxUsage, mailboxUsage + senderUsage} {
		var plan []string
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+q, 1, "alice")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		if p := strings.Join(plan, "; "); !strings.Contains(p, "COVERING INDEX mailbox_usage") {
			t.Errorf("%s: plan %q", q, p)
		}
	}
}

func TestMemoryDatabaseOutlivesIdleTimeout(t *testing.T) {
	defer func(d time.Duration) { connMaxIdleTime = d }(connMaxIdleTime)
	connMaxIdleTime = 10 * time.Millisecond

	s := openTest(t)
	addUser(t, s, "alice")
	// database/sql looks for idle connections at most once a second.
	time.Sleep(1500 * time.Millisecond)
	if _, err := s.UserByName(context.Background(), "alice"); err != nil {
		t.Fatalf("in-memory database lost while idle: %v", err)
	}
}
