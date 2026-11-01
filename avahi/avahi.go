// SPDX-License-Identifier: LGPL-3.0-or-later

// Package avahi is a stunmesh-go plugin that wraps another and lets peers on
// the same LAN use LAN addresses. It advertises the WireGuard device over
// mDNS (an avahi static service), and when a peer shares our public IPv4 and
// is visible over mDNS, answers Get with the peer's LAN address instead of its
// public one. Everything else goes to the wrapped instance unchanged.
//
//	plugins:
//	  dht:
//	    type: builtin
//	    name: opendht
//	    endpoints: ["http://dhtproxy2.jami.net"]
//	  mesh:
//	    type: builtin
//	    name: avahi
//	    next: dht
package avahi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"github.com/tjjh89017/stunmesh-go/pluginapi/endpoint"

	"github.com/tarasglek/stunmesh-avahi/internal/wgdev"
)

const (
	serviceType = "_wgmesh._udp"
	servicesDir = "/etc/avahi/services"
)

func init() { pluginapi.RegisterWithStores("avahi", New) }

type config struct {
	Next string `mapstructure:"next"`
}

// New builds the store from its config: next, the plugin instance it wraps.
func New(ctx context.Context, raw pluginapi.PluginConfig, stores pluginapi.PluginStores) (pluginapi.Store, error) {
	var cfg config
	if err := pluginapi.DecodeConfig(ctx, raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Next == "" {
		return nil, errors.New("avahi: next is required")
	}
	inner, err := stores.Lookup(cfg.Next)
	if err != nil {
		return nil, err
	}
	return newStore(inner, wgdev.Read, browse, func(dev, xml string) error {
		return writeIfChanged(filepath.Join(servicesDir, "stunmesh-"+dev+".service"), xml)
	}), nil
}

type Store struct {
	inner         pluginapi.Store
	device        func(name string) (wgdev.Device, error)
	browse        func(context.Context) string
	publish       func(dev, serviceXML string) error
	mu            sync.Mutex
	ourPublicHost map[string]string // per device, from the last record we published
}

func newStore(inner pluginapi.Store, device func(string) (wgdev.Device, error), browse func(context.Context) string, publish func(string, string) error) *Store {
	return &Store{inner: inner, device: device, browse: browse, publish: publish, ourPublicHost: map[string]string{}}
}

func (s *Store) Set(ctx context.Context, req pluginapi.PluginRequest) error {
	d, _, ok := wgdev.Lookup(s.device, req)
	if !ok {
		return s.inner.Set(ctx, req)
	}
	// Rewritten only when it changes, so this is not a flash write per tick.
	if err := s.publish(req.Device, serviceXML(req.Device, d)); err != nil {
		// LAN discovery is optional; still publish.
		zerolog.Ctx(ctx).Warn().Err(err).Str("plugin", "avahi").Msg("service file")
	}
	if host := publicHost(d, req.PeerPublicKey, req.Value); host != "" {
		s.mu.Lock()
		s.ourPublicHost[req.Device] = host
		s.mu.Unlock()
	}
	return s.inner.Set(ctx, req)
}

func (s *Store) Get(ctx context.Context, req pluginapi.PluginRequest) (string, error) {
	record, err := s.inner.Get(ctx, req)
	d, _, ok := wgdev.Lookup(s.device, req)
	if !ok {
		return record, err
	}
	if answer, ok := s.lanAnswer(ctx, d, req, record, err); ok {
		return answer, nil
	}
	return record, err
}

// lanAnswer returns a sealed LAN endpoint when the peer is behind our public
// IP (or the backend has no record) and avahi sees it.
func (s *Store) lanAnswer(ctx context.Context, d wgdev.Device, req pluginapi.PluginRequest, record string, backendErr error) (string, bool) {
	if backendErr == nil && record != "" {
		s.mu.Lock()
		ours := s.ourPublicHost[req.Device]
		s.mu.Unlock()
		if h := publicHost(d, req.PeerPublicKey, record); h == "" || h != ours {
			return "", false // peer is elsewhere: stale mDNS must not win
		}
	}
	lan := findLANEndpoint(s.browse(ctx), req.PeerPublicKey)
	if lan == "" {
		return "", false
	}
	msg, _ := json.Marshal(map[string]string{"ipv4": lan})
	sealed, err := endpoint.Seal(msg, req.PeerPublicKey, d.PrivateKey)
	return sealed, err == nil
}

// publicHost returns the IPv4 host in a record exchanged with peer, or "".
// Records in both directions open with the same key.
func publicHost(d wgdev.Device, peer [32]byte, record string) string {
	msg, err := endpoint.Open(record, peer, d.PrivateKey)
	var ep struct {
		IPv4 string `json:"ipv4"`
	}
	if err != nil || json.Unmarshal(msg, &ep) != nil {
		return ""
	}
	host, _, _ := net.SplitHostPort(ep.IPv4)
	return host
}

func serviceXML(dev string, d wgdev.Device) string {
	return fmt.Sprintf(`<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">stunmesh %%h %s</name>
  <service>
    <type>%s</type>
    <port>%d</port>
    <txt-record>pk=%s</txt-record>
  </service>
</service-group>
`, dev, serviceType, d.ListenPort, base64.StdEncoding.EncodeToString(d.PublicKey[:]))
}

// writeIfChanged replaces path atomically when its contents differ.
func writeIfChanged(path, data string) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == data {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func browse(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "avahi-browse", "-rptk", serviceType).Output()
	return string(out)
}

// findLANEndpoint finds the peer's IPv4 ip:port in `avahi-browse -rpt` output.
func findLANEndpoint(browseOutput string, peer [32]byte) string {
	txt := `"pk=` + base64.StdEncoding.EncodeToString(peer[:]) + `"`
	for _, line := range strings.Split(browseOutput, "\n") {
		f := strings.Split(line, ";")
		if len(f) >= 10 && f[0] == "=" && f[1] != "lo" && f[2] == "IPv4" && strings.Contains(f[9], txt) {
			return net.JoinHostPort(f[7], f[8])
		}
	}
	return ""
}
