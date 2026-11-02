// SPDX-License-Identifier: LGPL-3.0-or-later

package lease

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"github.com/tjjh89017/stunmesh-go/pluginapi/endpoint"

	"github.com/tarasglek/stunmesh-avahi/internal/wgdev"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// proxy is a fake OpenDHT listen endpoint. Each connection gets the lines
// sent on lines until it is closed, or hangs up at once if eof is set.
type proxy struct {
	*httptest.Server
	conns atomic.Int32
	lines chan string
	eof   bool
}

func newProxy(t *testing.T, eof bool) *proxy {
	p := &proxy{lines: make(chan string, 8), eof: eof}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.conns.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/listen") {
			t.Errorf("request to %s", r.URL.Path)
		}
		w.(http.Flusher).Flush()
		if p.eof {
			return
		}
		for {
			select {
			case l := <-p.lines:
				fmt.Fprintln(w, l)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(p.Close)
	return p
}

// wnode is a node whose clock, peer and log are safe to share with watch
// goroutines.
type wnode struct {
	aPub, aPriv, bPub, bPriv [32]byte
	backend                  *fakeStore
	store                    *Store
	log                      syncBuf
	mu                       sync.Mutex
	now                      time.Time
	peer                     wgdev.Peer
}

func newWatchNode(t *testing.T, listen string) *wnode {
	n := &wnode{backend: &fakeStore{data: map[string]string{}}, now: time.Unix(1_800_000_000, 0)}
	n.aPub, n.aPriv = keypair(t)
	n.bPub, n.bPriv = keypair(t)
	n.peer = wgdev.Peer{PublicKey: n.bPub, Keepalive: 25 * time.Second}
	n.store = newStore(n.backend, 25*time.Second,
		func(string) (wgdev.Device, error) {
			n.mu.Lock()
			defer n.mu.Unlock()
			return wgdev.Device{PrivateKey: n.aPriv, PublicKey: n.aPub, Peers: []wgdev.Peer{n.peer}}, nil
		},
		func(_ string, _ [32]byte, d time.Duration) error {
			n.mu.Lock()
			defer n.mu.Unlock()
			n.peer.Keepalive = d
			return nil
		},
		func() time.Time {
			n.mu.Lock()
			defer n.mu.Unlock()
			return n.now
		})
	n.store.retry = 10 * time.Millisecond
	if listen != "" {
		n.store.listen = []string{listen}
	}
	t.Cleanup(func() { n.store.Close() })
	return n
}

func (n *wnode) get() {
	ctx := zerolog.New(&n.log).Level(zerolog.DebugLevel).WithContext(context.Background())
	n.store.Get(ctx, pluginapi.PluginRequest{Device: "wgmesh", LocalPublicKey: n.aPub, PeerPublicKey: n.bPub, Key: endpoint.Key(n.bPub, n.aPub)})
}

func (n *wnode) advance(d time.Duration) {
	n.mu.Lock()
	n.now = n.now.Add(d)
	n.mu.Unlock()
}

func (n *wnode) keepalive() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peer.Keepalive
}

// value is a listen line holding a record b published for a, ts old.
func (n *wnode) value(t *testing.T, age time.Duration) string {
	rec := seal(t, `{"ipv4":"198.51.100.9:51821"}`, n.aPub, n.bPriv)
	env, _ := json.Marshal(map[string]any{"magic": "stunmesh-v1", "ts": n.now.Add(-age).Unix(), "data": rec})
	line, _ := json.Marshal(map[string]any{"data": base64.StdEncoding.EncodeToString(env), "id": "1", "type": 0})
	return string(line)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (n *wnode) logged(s string) func() bool {
	return func() bool { return strings.Contains(n.log.String(), s) }
}

func TestWatchPushBringsPeerBack(t *testing.T) {
	p := newProxy(t, false)
	n := newWatchNode(t, p.URL)
	n.get() // away: keepalive off, watch opened, next poll in 1 min
	eventually(t, "listen opened", n.logged(`"listen opened"`))
	if n.keepalive() != 0 {
		t.Fatalf("keepalive = %v, want off while away", n.keepalive())
	}
	n.advance(20 * time.Second)
	p.lines <- n.value(t, 13*time.Second)
	eventually(t, "peer back", n.logged(`"peer back"`))
	out := n.log.String()
	for _, w := range []string{`"source":"push"`, `"poll_due_in":"40s"`} {
		if !strings.Contains(out, w) {
			t.Errorf("log lacks %s:\n%s", w, out)
		}
	}
	if c := strings.Count(out, `"plugin":"lease"`) - strings.Count(out, `"message"`); c != 0 {
		t.Errorf("log lines repeat fields:\n%s", out)
	}
	if n.keepalive() != 25*time.Second {
		t.Errorf("keepalive = %v, want restored by the push", n.keepalive())
	}
	eventually(t, "listen ended", n.logged(`"reason":"present"`))
	n.store.Close() // waits for the watch goroutine
	if c := p.conns.Load(); c != 1 {
		t.Errorf("%d listen connections, want 1: no reopen once present", c)
	}
}

func TestWatchIgnoresStaleAndForeignValues(t *testing.T) {
	p := newProxy(t, false)
	n := newWatchNode(t, p.URL)
	n.get()
	eventually(t, "listen opened", n.logged(`"listen opened"`))
	p.lines <- n.value(t, 12*time.Minute) // a copy the listening proxy failed to expire
	p.lines <- strings.Replace(n.value(t, 0), `"data":"`, `"data":"AA`, 1)
	k, _ := keypair(t) // fresh, but sealed by someone else
	rec := seal(t, `{"ipv4":"192.0.2.1:1"}`, n.aPub, k)
	env, _ := json.Marshal(map[string]any{"ts": n.now.Unix(), "data": rec})
	p.lines <- `{"data":"` + base64.StdEncoding.EncodeToString(env) + `"}`
	eventually(t, "three values ignored", func() bool { return strings.Count(n.log.String(), `"value ignored"`) == 3 })
	out := n.log.String()
	for _, w := range []string{`"why":"stale 12m0s"`, `"why":"unparsable"`, `"why":"unopenable"`} {
		if !strings.Contains(out, w) {
			t.Errorf("log lacks %s:\n%s", w, out)
		}
	}
	if strings.Contains(out, `"peer back"`) || n.keepalive() != 0 {
		t.Errorf("peer marked back by an ignored value")
	}
	n.store.Close()
	if !strings.Contains(n.log.String(), `"reason":"close"`) {
		t.Errorf("Close did not end the stream:\n%s", n.log.String())
	}
}

func TestWatchReopensAfterEOFAndPollStillRuns(t *testing.T) {
	p := newProxy(t, true)
	n := newWatchNode(t, p.URL)
	n.get()
	eventually(t, "a reopen", func() bool { return p.conns.Load() >= 2 })
	if !strings.Contains(n.log.String(), `"reason":"eof"`) {
		t.Errorf("log lacks reason eof:\n%s", n.log.String())
	}
	// The poll finds the record while the watch is open: a missed push.
	n.backend.data[endpoint.Key(n.bPub, n.aPub)] = "rec"
	n.advance(time.Minute)
	n.get()
	out := n.log.String()
	for _, w := range []string{`"source":"poll"`, `"watch_age":"1m0s"`} {
		if !strings.Contains(out, w) {
			t.Errorf("log lacks %s:\n%s", w, out)
		}
	}
	c := p.conns.Load()
	n.store.Close() // waits for the watch goroutine
	if p.conns.Load() > c+1 {
		t.Errorf("stream reopened after the peer came back")
	}
}

func TestWatchBacksOffWhenProxyFails(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	n := newWatchNode(t, srv.URL)
	n.get()
	// retry is 10ms: fixed, 200ms would allow ~20 attempts; doubling
	// (10, 20, 40, 80ms) allows at most 5.
	time.Sleep(200 * time.Millisecond)
	n.store.Close()
	if c := conns.Load(); c < 2 || c > 5 {
		t.Errorf("%d attempts in 200ms, want 2..5: failed streams must back off", c)
	}
	if !strings.Contains(n.log.String(), `"reason":"error: 503 Service Unavailable"`) {
		t.Errorf("log lacks the status:\n%s", n.log.String())
	}
}

func TestWatchHandshakeReturnIsNotAMissedPush(t *testing.T) {
	p := newProxy(t, false)
	n := newWatchNode(t, p.URL)
	n.get()
	eventually(t, "listen opened", n.logged(`"listen opened"`))
	n.mu.Lock()
	n.peer.Endpoint, n.peer.LastHandshake = "203.0.113.9:51821", n.now
	n.mu.Unlock()
	n.get()
	out := n.log.String()
	if !strings.Contains(out, `"source":"handshake"`) || strings.Contains(out, "watch_age") {
		t.Errorf("handshake return logged as a missed push:\n%s", out)
	}
}

func TestWatchMovesToNextProxyWhenOneIsDown(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	t.Cleanup(down.Close)
	up := newProxy(t, false)
	n := newWatchNode(t, "")
	n.store.listen = []string{down.URL, up.URL}
	n.get()
	eventually(t, "listen opened on the second proxy", n.logged(`"proxy":"`+up.URL+`","message":"listen opened"`))
	up.lines <- n.value(t, 0)
	eventually(t, "peer back", n.logged(`"source":"push"`))
}

func TestNewWatchesByDefaultWithKeepalive(t *testing.T) {
	stores := fakeStores{"dht": &fakeStore{data: map[string]string{}}}
	for _, c := range []struct {
		cfg  pluginapi.PluginConfig
		want int
	}{
		{pluginapi.PluginConfig{"next": "dht", "keepalive": "25s"}, len(listenProxies)},
		{pluginapi.PluginConfig{"next": "dht"}, 0},
	} {
		st, err := New(context.Background(), c.cfg, stores)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(st.(*Store).listen); got != c.want {
			t.Errorf("%v: %d proxies, want %d", c.cfg, got, c.want)
		}
	}
}

type fakeStores map[string]pluginapi.Store

func (f fakeStores) Lookup(name string) (pluginapi.Store, error) { return f[name], nil }
