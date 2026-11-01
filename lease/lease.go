// SPDX-License-Identifier: LGPL-3.0-or-later

// Package lease is a Store that wraps a backend whose values expire, such as
// OpenDHT (10 minutes), and keeps it alive with as few calls as possible:
//
//   - Set goes to the backend when our endpoint changed, or when the last
//     successful publish of the same endpoint is older than republish.
//     Records are sealed with a fresh nonce each time, so the comparison is
//     on the opened plaintext.
//
//   - Get answers with WireGuard's live endpoint for the peer while its last
//     handshake is younger than fresh, without asking the backend. A
//     handshake proves the peer is reachable there, and answering with the
//     live endpoint (not a cached record) cannot undo a roam WireGuard has
//     already followed. A stale handshake asks the backend as usual.
//
// Keep republish + refresh_interval under the backend's expiry: the default
// 7m30s suits a 1 minute tick against OpenDHT's 10 minutes, and would
// republish too late at upstream's default 10 minute tick. Live answers are
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
//	    republish: 7m30s  # default; keep under the backend's expiry
//	    fresh: 3m         # default; above WireGuard's ~2 min rekey
//	    keepalive: 25s    # default off; interval to restore for present peers
package lease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Republish time.Duration `mapstructure:"republish"`
	Fresh     time.Duration `mapstructure:"fresh"`
	Keepalive time.Duration `mapstructure:"keepalive"`
}

// New builds the store from its config: next, the plugin instance it wraps,
// and optional durations.
func New(ctx context.Context, raw pluginapi.PluginConfig, stores pluginapi.PluginStores) (pluginapi.Store, error) {
	cfg := config{Republish: 7*time.Minute + 30*time.Second, Fresh: 3 * time.Minute}
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
	return newStore(inner, cfg.Republish, cfg.Fresh, cfg.Keepalive, wgdev.Read, wgdev.SetKeepalive, wallClock), nil
}

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
	inner            pluginapi.Store
	republish, fresh time.Duration
	keepalive        time.Duration // 0: leave WireGuard keepalives alone
	device           func(name string) (wgdev.Device, error)
	setKeepalive     func(device string, peer [32]byte, interval time.Duration) error
	now              func() time.Time
	mu               sync.Mutex
	last             map[string]published
	away             map[string]away
}

func newStore(inner pluginapi.Store, republish, fresh, keepalive time.Duration, device func(string) (wgdev.Device, error), setKeepalive func(string, [32]byte, time.Duration) error, now func() time.Time) *Store {
	return &Store{inner: inner, republish: republish, fresh: fresh, keepalive: keepalive, device: device, setKeepalive: setKeepalive, now: now, last: map[string]published{}, away: map[string]away{}}
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
		if age := s.now().Sub(p.at); ok && bytes.Equal(p.plaintext, plaintext) && age >= 0 && age < s.republish {
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
		s.present(ctx, req, peer)
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
	s.present(ctx, req, peer)
	return record, nil
}

// gone marks peer away after a failed lookup and schedules the next one, in
// 1, 2, 4, 4... minutes.
func (s *Store) gone(ctx context.Context, req pluginapi.PluginRequest, peer wgdev.Peer, a away, err error) {
	a.fails++
	a.next = s.now().Add(min(time.Minute<<min(a.fails-1, 2), maxBackoff))
	s.mu.Lock()
	s.away[req.Key] = a
	s.mu.Unlock()
	if a.fails == 1 {
		// The error tells "no value" (peer gone) from a backend outage.
		zerolog.Ctx(ctx).Info().Err(err).Str("plugin", "lease").Str("peer", pluginapi.Key(peer.PublicKey).String()[:8]).Msg("peer away")
	}
	s.setPeerKeepalive(ctx, req.Device, peer, 0)
}

// present clears a peer's away state and restores its keepalive.
func (s *Store) present(ctx context.Context, req pluginapi.PluginRequest, peer wgdev.Peer) {
	s.mu.Lock()
	_, wasAway := s.away[req.Key]
	delete(s.away, req.Key)
	s.mu.Unlock()
	if wasAway {
		zerolog.Ctx(ctx).Info().Str("plugin", "lease").Str("peer", pluginapi.Key(peer.PublicKey).String()[:8]).Msg("peer back")
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
	return !p.LastHandshake.IsZero() && s.now().Sub(p.LastHandshake) < s.fresh
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
