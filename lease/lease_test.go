// SPDX-License-Identifier: LGPL-3.0-or-later

package lease

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"github.com/tjjh89017/stunmesh-go/pluginapi/endpoint"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tarasglek/stunmesh-avahi/internal/wgdev"
)

func keypair(t *testing.T) (pub, priv [32]byte) {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey(), k
}

func seal(t *testing.T, msg string, peerPub, priv [32]byte) string {
	t.Helper()
	rec, err := endpoint.Seal([]byte(msg), peerPub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func open(t *testing.T, record string, peerPub, priv [32]byte) string {
	t.Helper()
	msg, err := endpoint.Open(record, peerPub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(msg)
}

type fakeStore struct {
	data   map[string]string
	setErr error
	sets   int
	gets   int
}

func (f *fakeStore) Get(_ context.Context, req pluginapi.PluginRequest) (string, error) {
	key := req.Key
	f.gets++
	v, ok := f.data[key]
	if !ok {
		return "", errors.New("no value")
	}
	return v, nil
}

func (f *fakeStore) Set(_ context.Context, req pluginapi.PluginRequest) error {
	key, value := req.Key, req.Value
	f.sets++
	if f.setErr != nil {
		return f.setErr
	}
	f.data[key] = value
	return nil
}

// node is node a with one peer b. Keepalive changes are applied to peer,
// as the kernel would, and counted.
type node struct {
	aPub, aPriv, bPub, bPriv [32]byte
	peer                     wgdev.Peer
	backend                  *fakeStore
	now                      time.Time
	keepaliveSets            int
	store                    *Store
}

func newNode(t *testing.T) *node { return newNodeKeepalive(t, 25*time.Second) }

func newNodeKeepalive(t *testing.T, keepalive time.Duration) *node {
	n := &node{backend: &fakeStore{data: map[string]string{}}, now: time.Unix(1_800_000_000, 0)}
	n.aPub, n.aPriv = keypair(t)
	n.bPub, n.bPriv = keypair(t)
	n.peer = wgdev.Peer{PublicKey: n.bPub, Keepalive: 25 * time.Second}
	n.store = newStore(n.backend, 7*time.Minute+30*time.Second, 3*time.Minute, keepalive,
		func(string) (wgdev.Device, error) {
			return wgdev.Device{PrivateKey: n.aPriv, PublicKey: n.aPub, Peers: []wgdev.Peer{n.peer}}, nil
		},
		func(_ string, peer [32]byte, d time.Duration) error {
			if peer != n.bPub {
				t.Fatalf("keepalive set for an unknown peer")
			}
			n.keepaliveSets++
			n.peer.Keepalive = d
			return nil
		},
		func() time.Time { return n.now })
	return n
}

func (n *node) setReq(value string) pluginapi.PluginRequest {
	return pluginapi.PluginRequest{Device: "wgmesh", LocalPublicKey: n.aPub, PeerPublicKey: n.bPub, Key: endpoint.Key(n.aPub, n.bPub), Value: value}
}

func (n *node) getReq() pluginapi.PluginRequest {
	return pluginapi.PluginRequest{Device: "wgmesh", LocalPublicKey: n.aPub, PeerPublicKey: n.bPub, Key: endpoint.Key(n.bPub, n.aPub)}
}

func (n *node) set(t *testing.T, ep string) error {
	t.Helper()
	// A fresh nonce each time, as stunmesh-go does.
	return n.store.Set(context.Background(), n.setReq(seal(t, `{"ipv4":"`+ep+`"}`, n.bPub, n.aPriv)))
}

func (n *node) get() (string, error) {
	return n.store.Get(context.Background(), n.getReq())
}

func TestSetFirstPublishGoesThrough(t *testing.T) {
	n := newNode(t)
	if err := n.set(t, "198.51.100.1:51820"); err != nil || n.backend.sets != 1 {
		t.Fatalf("sets=%d err=%v, want 1 nil", n.backend.sets, err)
	}
}

func TestSetUnchangedWithinLeaseIsSkipped(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.now = n.now.Add(7 * time.Minute)
	if err := n.set(t, "198.51.100.1:51820"); err != nil || n.backend.sets != 1 {
		t.Fatalf("sets=%d err=%v, want 1 nil", n.backend.sets, err)
	}
}

func TestSetUnchangedAfterLeaseIsRepublished(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.now = n.now.Add(7*time.Minute + 30*time.Second)
	n.set(t, "198.51.100.1:51820")
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestSetLeaseCountsFromLastPublishNotFirst(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.now = n.now.Add(8 * time.Minute)
	n.set(t, "198.51.100.1:51820") // republished
	n.now = n.now.Add(7 * time.Minute)
	n.set(t, "198.51.100.1:51820") // within the new lease
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestSetChangedEndpointGoesThroughImmediately(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.now = n.now.Add(time.Minute)
	n.set(t, "198.51.100.2:51820")
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestSetFailureIsRetriedNextTime(t *testing.T) {
	n := newNode(t)
	n.backend.setErr = errors.New("proxy down")
	if err := n.set(t, "198.51.100.1:51820"); err == nil {
		t.Fatal("backend error swallowed")
	}
	n.backend.setErr = nil
	n.now = n.now.Add(time.Minute)
	n.set(t, "198.51.100.1:51820")
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestSetUnopenableRecordAlwaysGoesThrough(t *testing.T) {
	n := newNode(t)
	n.store.Set(context.Background(), n.setReq("00"))
	n.store.Set(context.Background(), n.setReq("00"))
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestGetFreshHandshakeAnswersLiveEndpoint(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "203.0.113.9:51821"
	n.peer.LastHandshake = n.now.Add(-2 * time.Minute)

	got, err := n.get()
	if err != nil {
		t.Fatal(err)
	}
	if n.backend.gets != 0 {
		t.Error("backend asked while the tunnel is up")
	}
	// stunmesh on node a opens the answer with (b pub, a priv).
	if msg := open(t, got, n.bPub, n.aPriv); msg != `{"ipv4":"203.0.113.9:51821"}` {
		t.Errorf("answer opens to %s", msg)
	}
}

func TestGetStaleHandshakeAsksBackend(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "203.0.113.9:51821"
	n.peer.LastHandshake = n.now.Add(-3 * time.Minute)
	n.backend.data[n.getReq().Key] = "rec"

	if got, err := n.get(); err != nil || got != "rec" || n.backend.gets != 1 {
		t.Fatalf("got %q, %v, gets=%d; want backend record", got, err, n.backend.gets)
	}
}

func TestGetNeverHandshakedAsksBackend(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "203.0.113.9:51821"
	n.backend.data[n.getReq().Key] = "rec"

	if got, _ := n.get(); got != "rec" {
		t.Fatalf("got %q, want backend record", got)
	}
}

func TestGetIPv6EndpointAsksBackend(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "[2001:db8::1]:51821"
	n.peer.LastHandshake = n.now
	n.backend.data[n.getReq().Key] = "rec"

	if got, _ := n.get(); got != "rec" {
		t.Fatalf("got %q, want backend record", got)
	}
}

func TestUnknownKeyPassesThrough(t *testing.T) {
	n := newNode(t)
	n.backend.data["ffff"] = "x"
	stranger := pluginapi.PluginRequest{Device: "wgmesh", PeerPublicKey: pluginapi.Key{9}, Key: "eeee", Value: "y"}
	n.store.Set(context.Background(), stranger)
	n.store.Set(context.Background(), stranger)
	if n.backend.sets != 2 {
		t.Errorf("sets=%d, want 2", n.backend.sets)
	}
	if got, err := n.store.Get(context.Background(), pluginapi.PluginRequest{Device: "wgmesh", PeerPublicKey: pluginapi.Key{9}, Key: "ffff"}); err != nil || got != "x" {
		t.Errorf("get not passed through: %q, %v", got, err)
	}
}

func TestSetClockStepBackwardRepublishes(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.now = n.now.Add(-time.Hour) // NTP step back: never skip into an expiry
	n.set(t, "198.51.100.1:51820")
	if n.backend.sets != 2 {
		t.Fatalf("sets=%d, want 2", n.backend.sets)
	}
}

func TestSetEndpointChangeWhileBackendDownIsRecorded(t *testing.T) {
	n := newNode(t)
	n.set(t, "198.51.100.1:51820")
	n.backend.setErr = errors.New("proxy down")
	n.now = n.now.Add(time.Minute)
	n.set(t, "198.51.100.2:51820")
	n.backend.setErr = nil
	n.now = n.now.Add(time.Minute)
	n.set(t, "198.51.100.2:51820") // goes through: the failed one was not recorded
	n.now = n.now.Add(time.Minute)
	n.set(t, "198.51.100.2:51820") // skipped: within the new lease
	if n.backend.sets != 3 {
		t.Fatalf("sets=%d, want 3", n.backend.sets)
	}
}

func TestNewRejectsKeepaliveWithoutUnit(t *testing.T) {
	_, err := New(context.Background(), pluginapi.PluginConfig{"next": "x", "keepalive": 25}, nil)
	if err == nil || !strings.Contains(err.Error(), "keepalive") {
		t.Fatalf("keepalive: 25 gave err = %v, want a keepalive error", err)
	}
}

// An away peer: the backend has no record and the handshake is stale.

func TestGetAwayBacksOff(t *testing.T) {
	n := newNode(t)
	steps := []struct {
		after     time.Duration
		wantCalls int
	}{
		{0, 1},                // first lookup fails: away, retry in 1 min
		{30 * time.Second, 1}, // within the backoff: no lookup
		{30 * time.Second, 2}, // 1 min: lookup, fails, retry in 2 min
		{time.Minute, 2},
		{time.Minute, 3},     // 2 min: lookup, retry in 4 min
		{3 * time.Minute, 3}, // still within 4 min
		{time.Minute, 4},     // 4 min: lookup, capped at 4 min from here on
		{4 * time.Minute, 5},
	}
	for i, st := range steps {
		n.now = n.now.Add(st.after)
		if _, err := n.get(); err == nil {
			t.Fatalf("step %d: Get() succeeded for an away peer", i)
		}
		if n.backend.gets != st.wantCalls {
			t.Fatalf("step %d: backend gets = %d, want %d", i, n.backend.gets, st.wantCalls)
		}
	}
}

func TestGetAwayTurnsKeepaliveOff(t *testing.T) {
	n := newNode(t)
	n.get()
	if n.peer.Keepalive != 0 || n.keepaliveSets != 1 {
		t.Fatalf("keepalive = %v after %d sets, want off after 1", n.peer.Keepalive, n.keepaliveSets)
	}
	n.now = n.now.Add(time.Minute)
	n.get()
	if n.keepaliveSets != 1 {
		t.Errorf("keepalive set %d times, want no change while already off", n.keepaliveSets)
	}
}

func TestGetRecordBackRestoresKeepaliveAndBackoff(t *testing.T) {
	n := newNode(t)
	n.get() // away
	n.backend.data[n.getReq().Key] = "rec"
	n.now = n.now.Add(time.Minute)
	if got, err := n.get(); err != nil || got != "rec" {
		t.Fatalf("Get() = %q, %v; want the record", got, err)
	}
	if n.peer.Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v, want restored to 25s", n.peer.Keepalive)
	}
	n.get() // back to normal: no backoff, asks every time
	if n.backend.gets != 3 {
		t.Errorf("backend gets = %d, want 3: no backoff once the record is back", n.backend.gets)
	}
}

func TestGetFreshHandshakeRestoresKeepalive(t *testing.T) {
	n := newNode(t)
	n.get() // away
	n.peer.Endpoint = "203.0.113.9:51821"
	n.peer.LastHandshake = n.now // the peer reached us on its own
	if _, err := n.get(); err != nil {
		t.Fatal(err)
	}
	if n.peer.Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v, want restored to 25s", n.peer.Keepalive)
	}
}

func TestGetRestoresKeepaliveLeftOffByEarlierRun(t *testing.T) {
	n := newNode(t)
	n.peer.Keepalive = 0 // a previous process turned it off and exited
	n.backend.data[n.getReq().Key] = "rec"
	n.get()
	if n.peer.Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v, want 25s", n.peer.Keepalive)
	}
}

func TestGetUpPeerKeepaliveUntouched(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "203.0.113.9:51821"
	n.peer.LastHandshake = n.now
	n.get()
	n.backend.data[n.getReq().Key] = "rec"
	n.peer.LastHandshake = time.Time{}
	n.get()
	if n.keepaliveSets != 0 {
		t.Errorf("keepalive set %d times for a present peer already at 25s", n.keepaliveSets)
	}
}

func TestGetKeepaliveUnmanagedByDefault(t *testing.T) {
	n := newNodeKeepalive(t, 0)
	n.get()
	if n.keepaliveSets != 0 || n.peer.Keepalive != 25*time.Second {
		t.Errorf("keepalive changed (%d sets) with keepalive management off", n.keepaliveSets)
	}
	n.now = n.now.Add(30 * time.Second)
	n.get()
	if n.backend.gets != 1 {
		t.Errorf("backend gets = %d, want the backoff to apply anyway", n.backend.gets)
	}
}

func TestGetAwayClockStepBackDoesNotStretchBackoff(t *testing.T) {
	n := newNode(t)
	n.get()                       // away, next lookup in 1 min
	n.now = n.now.Add(-time.Hour) // NTP step back: the wait must not become an hour
	n.get()
	if n.backend.gets != 2 {
		t.Fatalf("backend gets = %d, want 2: a wait longer than the cap counts as over", n.backend.gets)
	}
}

func TestGetFreshHandshakeIsNeverAway(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "[2001:db8::1]:51821" // not answerable live, but the tunnel is up
	n.peer.LastHandshake = n.now
	if _, err := n.get(); err == nil {
		t.Fatal("Get() succeeded, want the backend's error")
	}
	if n.keepaliveSets != 0 {
		t.Fatalf("keepalive changed for a peer with a fresh handshake")
	}
	n.get()
	if n.backend.gets != 2 {
		t.Errorf("backend gets = %d, want 2: a fresh handshake is never backed off", n.backend.gets)
	}
}

func TestGetAwayDuringBackoffAnswersCurrentEndpoint(t *testing.T) {
	n := newNode(t)
	n.peer.Endpoint = "198.51.100.7:51821"
	n.get() // away
	n.now = n.now.Add(30 * time.Second)
	got, err := n.get()
	if err != nil {
		t.Fatalf("Get() during backoff = %v, want WireGuard's current endpoint", err)
	}
	if n.backend.gets != 1 {
		t.Errorf("backend gets = %d, want 1: no lookup during backoff", n.backend.gets)
	}
	if msg := open(t, got, n.bPub, n.aPriv); msg != `{"ipv4":"198.51.100.7:51821"}` {
		t.Errorf("answer opens to %s", msg)
	}
}

func TestGetEmptyRecordIsAway(t *testing.T) {
	n := newNode(t)
	n.backend.data[n.getReq().Key] = "" // the Store contract's "nothing stored"
	n.get()
	if n.peer.Keepalive != 0 {
		t.Errorf("keepalive = %v, want off: an empty record means away", n.peer.Keepalive)
	}
}
