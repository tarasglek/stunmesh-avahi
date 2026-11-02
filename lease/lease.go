// SPDX-License-Identifier: LGPL-3.0-or-later

// Package lease is a Store that wraps a backend whose values expire, such as
// OpenDHT (10 minutes), and keeps it alive with as few calls as possible:
//
//   - Set goes to the backend when our endpoint changed, or when the last
//     successful publish of the same endpoint is older than 7m30s.
//     Records are sealed with a fresh nonce each time, so the comparison is
//     on the opened plaintext.
//
//   - Get answers with WireGuard's live endpoint for the peer while its last
//     handshake is younger than 3 minutes, without asking the backend. A
//     handshake proves the peer is reachable there, and answering with the
//     live endpoint (not a cached record) cannot undo a roam WireGuard has
//     already followed. A stale handshake asks the backend as usual.
//
// The republish interval suits OpenDHT's 10 minute expiry with
// refresh_interval at most 2 minutes; at upstream's default 10 minute tick
// it would republish too late. Live answers are
// IPv4 only, so use it on IPv4 devices: a dualstack device would get a record
// without its IPv6 endpoint.
//
// Ages use the wall clock. A step either way can only cause an early
// republish, never a missed one: a forward step makes a publish look older,
// and a backward step gives a negative age, which counts as expired.
//
// A peer with no record and no fresh handshake has not published for a
// whole expiry period and is away: Get looks it up again after 1, 2, then
// every 4 minutes and, if keepalive is set, turns that peer's WireGuard
// persistent keepalive off so WireGuard stops retrying handshakes to it. A
// record or a fresh handshake brings it back: lookups every tick and the
// keepalive set to the configured interval, which should match the
// WireGuard config. Unset, lease leaves keepalives alone. During backoff Get
// answers with the endpoint WireGuard has; a peer that never had one gets an
// error instead, which avahi above treats as no record and browses mDNS for.
//
// With keepalive set, lease also watches each away peer's key on Jami's
// OpenDHT proxies (GET /key/<k>/listen) and treats a fresh record there as
// the peer being back: keepalive is restored at once, and the kernel sends
// one packet on 0 -> non-zero, which reopens our NAT's filter for the peer
// so its handshakes get in. Without it a waking peer is only let in after
// our next backoff lookup. The backoff lookups continue unchanged, so the
// log shows whether the push or the poll saw the peer first. The proxies
// are interchangeable: each stream uses the next one, so one that is down
// is skipped. A stream that ends is reopened while the peer is still away.
//
// Config:
//
//	plugins:
//	  dht:
//	    type: builtin
//	    name: opendht
//	    endpoints: ["http://dhtproxy2.jami.net"]
//	  leased:
//	    type: builtin
//	    name: lease
//	    next: dht
//	    keepalive: 25s  # default off; interval to restore for present peers
package lease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"github.com/tjjh89017/stunmesh-go/pluginapi/endpoint"

	"github.com/tarasglek/stunmesh-avahi/internal/wgdev"
)

func init() { pluginapi.RegisterWithStores("lease", New) }

type config struct {
	Next      string        `mapstructure:"next"`
	Keepalive time.Duration `mapstructure:"keepalive"`
}

// New builds the store from its config: next, the plugin instance it wraps,
// and optional durations.
func New(ctx context.Context, raw pluginapi.PluginConfig, stores pluginapi.PluginStores) (pluginapi.Store, error) {
	var cfg config
	if err := pluginapi.DecodeConfig(ctx, raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Next == "" {
		return nil, errors.New("lease: next is required")
	}
	// A bare number decodes as nanoseconds: `keepalive: 25` would turn
	// keepalives off.
	if cfg.Keepalive != 0 && cfg.Keepalive < time.Second {
		return nil, fmt.Errorf("lease: keepalive: %v is under a second; give a unit, such as \"25s\"", cfg.Keepalive)
	}
	inner, err := stores.Lookup(cfg.Next)
	if err != nil {
		return nil, err
	}
	s := newStore(inner, cfg.Keepalive, wgdev.Read, wgdev.SetKeepalive, wallClock)
	if cfg.Keepalive != 0 {
		// Turning keepalive off for away peers is what makes our NAT drop
		// them when they wake, so the watch comes with it.
		s.listen = listenProxies
	}
	return s, nil
}

const (
	// republish is how old a publish of an unchanged endpoint may get:
	// OpenDHT's 10 minute expiry less two 1 minute ticks and a margin.
	republish = 7*time.Minute + 30*time.Second
	// fresh is how recent a handshake must be to skip a lookup: above
	// WireGuard's 2 minute rekey under keepalive.
	fresh = 3 * time.Minute
)

// listenProxies is the OpenDHT proxies to watch away peers on, plain http
// like the records they carry, which are sealed.
var listenProxies = []string{"http://dhtproxy2.jami.net", "http://dhtproxy3.jami.net"}

// wallClock strips Go's monotonic reading, which stops while a machine is
// suspended: a laptop that slept past the backend's expiry must republish on
// wake, not skip because the monotonic clock says little time passed.
func wallClock() time.Time { return time.Now().Round(0) }

type published struct {
	plaintext []byte
	at        time.Time
}

// away is a peer the wrapped instance had no record for.
type away struct {
	fails int
	next  time.Time // no lookup before this
}

// maxBackoff caps the wait between lookups of an away peer, and so how late
// a returning peer is noticed.
const maxBackoff = 4 * time.Minute

type Store struct {
	inner        pluginapi.Store
	keepalive    time.Duration // 0: leave WireGuard keepalives alone
	device       func(name string) (wgdev.Device, error)
	setKeepalive func(device string, peer [32]byte, interval time.Duration) error
	now          func() time.Time
	listen       []string      // OpenDHT proxy URLs to watch away peers on; nil off
	retry        time.Duration // wait before reopening an ended stream
	mu           sync.Mutex
	last         map[string]published
	away         map[string]away
	watches      map[string]*watch
	wg           sync.WaitGroup
}

func newStore(inner pluginapi.Store, keepalive time.Duration, device func(string) (wgdev.Device, error), setKeepalive func(string, [32]byte, time.Duration) error, now func() time.Time) *Store {
	return &Store{inner: inner, keepalive: keepalive, device: device, setKeepalive: setKeepalive, now: now, retry: 30 * time.Second, last: map[string]published{}, away: map[string]away{}, watches: map[string]*watch{}}
}

// Set is not reentrant per key: the core publishes sequentially
// (internal/ctrl/publish.go), so mu only guards the map.
func (s *Store) Set(ctx context.Context, req pluginapi.PluginRequest) error {
	plaintext := s.open(req)
	if plaintext != nil {
		s.mu.Lock()
		p, ok := s.last[req.Key]
		s.mu.Unlock()
		// A negative age is a clock stepped back: publish rather than skip
		// into an expiry.
		if age := s.now().Sub(p.at); ok && bytes.Equal(p.plaintext, plaintext) && age >= 0 && age < republish {
			return nil
		}
	}
	if err := s.inner.Set(ctx, req); err != nil {
		return err
	}
	if plaintext != nil {
		s.mu.Lock()
		s.last[req.Key] = published{plaintext, s.now()}
		s.mu.Unlock()
	}
	return nil
}

// open returns the plaintext of the record we publish for the request's
// peer, or nil when the peer is unknown or the record does not open.
func (s *Store) open(req pluginapi.PluginRequest) []byte {
	d, _, ok := wgdev.Lookup(s.device, req)
	if !ok {
		return nil
	}
	msg, err := endpoint.Open(req.Value, req.PeerPublicKey, d.PrivateKey)
	if err != nil {
		return nil
	}
	return msg
}

func (s *Store) Get(ctx context.Context, req pluginapi.PluginRequest) (string, error) {
	d, peer, ok := wgdev.Lookup(s.device, req)
	if !ok {
		return s.inner.Get(ctx, req)
	}
	key := req.Key
	if s.handshakeFresh(peer) {
		// The tunnel is up, so the peer is present whatever the backend says.
		s.present(ctx, req, peer, "handshake")
		if sealed, ok := answer(d, peer); ok {
			return sealed, nil
		}
		return s.inner.Get(ctx, req)
	}
	s.mu.Lock()
	a, isAway := s.away[key]
	s.mu.Unlock()
	// No wait left, or more than the cap (a clock stepped back): look now.
	if wait := a.next.Sub(s.now()); isAway && wait > 0 && wait <= maxBackoff {
		// Answering with the endpoint WireGuard already has changes nothing
		// in the core, and spares a warning and an avahi browse per tick.
		if sealed, ok := answer(d, peer); ok {
			return sealed, nil
		}
		return "", fmt.Errorf("lease: peer away, next lookup in %s", wait.Round(time.Second))
	}
	record, err := s.inner.Get(ctx, req)
	if err != nil || record == "" { // "" is the Store contract's "nothing stored"
		if err == nil {
			err = errors.New("no record")
		}
		s.gone(ctx, req, peer, a, err)
		return record, err
	}
	s.present(ctx, req, peer, "poll")
	return record, nil
}

// gone marks peer away after a failed lookup and schedules the next one, in
// 1, 2, 4, 4... minutes.
func (s *Store) gone(ctx context.Context, req pluginapi.PluginRequest, peer wgdev.Peer, a away, err error) {
	a.fails++
	a.next = s.now().Add(min(time.Minute<<min(a.fails-1, 2), maxBackoff))
	s.mu.Lock()
	s.away[req.Key] = a
	if len(s.listen) > 0 && s.watches[req.Key] == nil {
		s.startWatch(ctx, req)
	}
	s.mu.Unlock()
	if a.fails == 1 {
		// The error tells "no value" (peer gone) from a backend outage.
		zerolog.Ctx(ctx).Info().Err(err).Str("plugin", "lease").Str("peer", pluginapi.Key(peer.PublicKey).String()[:8]).Msg("peer away")
	}
	s.setPeerKeepalive(ctx, req.Device, peer, 0)
}

// present clears a peer's away state, stops its watch and restores its
// keepalive. source says what showed the peer is back: a fresh "handshake",
// a "poll" that found its record, or a "push" from the watch.
func (s *Store) present(ctx context.Context, req pluginapi.PluginRequest, peer wgdev.Peer, source string) {
	s.mu.Lock()
	a, wasAway := s.away[req.Key]
	delete(s.away, req.Key)
	w := s.watches[req.Key]
	delete(s.watches, req.Key)
	s.mu.Unlock()
	if wasAway {
		ev := zerolog.Ctx(ctx).Info().Str("plugin", "lease").Str("peer", pluginapi.Key(peer.PublicKey).String()[:8]).
			Str("source", source)
		switch {
		case source == "push":
			// How much sooner than the poll the push was; negative when
			// the poll was already due but its tick had not run.
			ev = ev.Str("poll_due_in", a.next.Sub(s.now()).Round(time.Second).String())
		case source == "poll" && w != nil:
			// The poll won while a stream was open: a missed push.
			ev = ev.Str("watch_age", s.now().Sub(w.started).Round(time.Second).String())
		}
		ev.Msg("peer back")
	}
	if w != nil {
		w.cancel(errPresent)
	}
	s.setPeerKeepalive(ctx, req.Device, peer, s.keepalive)
}

// setPeerKeepalive writes to WireGuard only when the interval differs.
func (s *Store) setPeerKeepalive(ctx context.Context, device string, peer wgdev.Peer, interval time.Duration) {
	if s.keepalive == 0 || peer.Keepalive == interval {
		return
	}
	if err := s.setKeepalive(device, peer.PublicKey, interval); err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Str("plugin", "lease").Str("peer", pluginapi.Key(peer.PublicKey).String()[:8]).Msg("set keepalive")
	}
}

// handshakeFresh reports whether WireGuard completed a handshake with p
// within fresh. wgctrl reports handshakes in wall time, the same clock as now.
func (s *Store) handshakeFresh(p wgdev.Peer) bool {
	return !p.LastHandshake.IsZero() && s.now().Sub(p.LastHandshake) < fresh
}

// answer seals the IPv4 endpoint WireGuard holds for p as a record.
func answer(d wgdev.Device, p wgdev.Peer) (string, bool) {
	ap, err := netip.ParseAddrPort(p.Endpoint)
	if err != nil || !ap.Addr().Is4() {
		return "", false
	}
	msg, _ := json.Marshal(map[string]string{"ipv4": p.Endpoint})
	sealed, err := endpoint.Seal(msg, p.PublicKey, d.PrivateKey)
	return sealed, err == nil
}

// pushMaxAge is how old a record from a listen stream may be and still count
// as the peer being back. OpenDHT expires values after 10 minutes, so an
// older one is a copy the proxy failed to drop; the minute between allows
// for clock skew. The ts is the publisher's and not sealed, so a replayed
// record with a fresh ts passes: that costs a restored keepalive until the
// next lookup marks the peer away again.
const pushMaxAge = 9 * time.Minute

// Why a watch was stopped, as context causes.
var (
	errPresent = errors.New("present")
	errClose   = errors.New("close")
)

// watch is an away peer's listen stream.
type watch struct {
	started time.Time
	cancel  context.CancelCauseFunc
}

// listenClient leaves TCP keepalive off: an idle stream then costs nothing,
// and the backoff lookups notice a peer that a dead stream missed. It dials
// directly, not through pluginapi/dialer, so it does not escape a tunnel
// that routes the proxy's address.
var listenClient = &http.Client{Transport: &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: -1}).DialContext,
	ResponseHeaderTimeout: 15 * time.Second,
}}

// startWatch runs req's peer's watch until present or Close stops it. Call
// with mu held. A stream that ends sooner than retry after it started, such
// as a refused connection or an error status, doubles the wait before the
// next one, up to maxBackoff, so a proxy that is down costs no more than
// the lookups.
func (s *Store) startWatch(ctx context.Context, req pluginapi.PluginRequest) {
	wctx, cancel := context.WithCancelCause(context.Background())
	s.watches[req.Key] = &watch{started: s.now(), cancel: cancel}
	base := zerolog.Ctx(ctx) // present adds plugin and peer itself
	log := base.With().Str("plugin", "lease").Str("peer", pluginapi.Key(req.PeerPublicKey).String()[:8]).Logger()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		wait := s.retry
		for i := 0; ; i++ {
			start := time.Now()
			s.stream(wctx, base, &log, req, s.listen[i%len(s.listen)])
			if time.Since(start) >= s.retry {
				wait = s.retry
			}
			select {
			case <-wctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, maxBackoff)
		}
	}()
}

// stream reads one listen stream until it ends, and calls present on the
// first fresh record of req's peer. log carries the plugin and peer fields;
// base, given to present, does not.
func (s *Store) stream(ctx context.Context, base, log *zerolog.Logger, req pluginapi.PluginRequest, proxy string) {
	opened, values := s.now(), 0
	reason := "eof"
	defer func() {
		if context.Cause(ctx) != nil {
			reason = context.Cause(ctx).Error()
		}
		log.Info().Str("proxy", proxy).Str("reason", reason).Str("age", s.now().Sub(opened).Round(time.Second).String()).Int("values", values).Msg("listen ended")
	}()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy+"/key/"+req.Key+"/listen", nil)
	if err != nil {
		reason = "error: " + err.Error()
		return
	}
	resp, err := listenClient.Do(hreq)
	if err != nil {
		reason = "error: " + err.Error()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		reason = "error: " + resp.Status
		return
	}
	log.Info().Str("proxy", proxy).Msg("listen opened")
	// Records are ~300 bytes, well under the scanner's 64 KB line limit.
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		values++
		if why := s.pushed(base.WithContext(ctx), req, sc.Bytes()); why != "" {
			log.Debug().Str("why", why).Msg("value ignored")
			continue
		}
		return
	}
	if sc.Err() != nil {
		reason = "error: " + sc.Err().Error()
	}
}

// pushed handles one line of a listen stream: a fresh record that opens
// with our key marks the peer present, logging to ctx's logger. It returns
// why a line was ignored, or "" when it was taken.
func (s *Store) pushed(ctx context.Context, req pluginapi.PluginRequest, line []byte) string {
	var v struct {
		Data string `json:"data"`
	}
	var env struct {
		Ts   int64  `json:"ts"`
		Data string `json:"data"`
	}
	raw, err := []byte(nil), json.Unmarshal(line, &v)
	if err == nil {
		raw, err = base64.StdEncoding.DecodeString(v.Data)
	}
	if err == nil {
		err = json.Unmarshal(raw, &env)
	}
	if err != nil {
		return "unparsable"
	}
	if age := s.now().Sub(time.Unix(env.Ts, 0)); age > pushMaxAge {
		return "stale " + age.Round(time.Second).String()
	}
	d, peer, ok := wgdev.Lookup(s.device, req)
	if !ok {
		return "unknown peer"
	}
	if _, err := endpoint.Open(env.Data, req.PeerPublicKey, d.PrivateKey); err != nil {
		return "unopenable"
	}
	s.present(ctx, req, peer, "push")
	return ""
}

// Close stops every watch and waits for them.
func (s *Store) Close() error {
	s.mu.Lock()
	for k, w := range s.watches {
		w.cancel(errClose)
		delete(s.watches, k)
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}
