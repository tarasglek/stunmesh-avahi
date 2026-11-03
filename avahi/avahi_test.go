// SPDX-License-Identifier: LGPL-3.0-or-later

package avahi

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"github.com/tjjh89017/stunmesh-go/pluginapi/endpoint"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tarasglek/stunmesh-avahi/wgdev"
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

// fakeStore is the backend: it records sets and answers gets from a map.
type fakeStore struct {
	data   map[string]string
	getErr error
	sets   int
}

func (f *fakeStore) Get(_ context.Context, req pluginapi.PluginRequest) (string, error) {
	key := req.Key
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.data[key]
	if !ok {
		return "", errors.New("no value")
	}
	return v, nil
}

func (f *fakeStore) Set(_ context.Context, req pluginapi.PluginRequest) error {
	f.sets++
	f.data[req.Key] = req.Value
	return nil
}

// node is node a with one peer b, both keypairs known to the test.
type node struct {
	aPub, aPriv, bPub, bPriv [32]byte
	backend                  *fakeStore
	browse                   string
	browses                  int
	service                  string
	store                    *Store
}

func newNode(t *testing.T) *node {
	n := &node{backend: &fakeStore{data: map[string]string{}}}
	n.aPub, n.aPriv = keypair(t)
	n.bPub, n.bPriv = keypair(t)
	dev := wgdev.Device{PrivateKey: n.aPriv, PublicKey: n.aPub, ListenPort: 51820, Peers: []wgdev.Peer{{PublicKey: n.bPub}}}
	n.store = newStore(n.backend,
		func(string) (wgdev.Device, error) { return dev, nil },
		func(context.Context) string { n.browses++; return n.browse },
		func(_, xml string) error { n.service = xml; return nil })
	return n
}

func (n *node) setReq(value string) pluginapi.PluginRequest {
	return pluginapi.PluginRequest{Device: "wgmesh", LocalPublicKey: n.aPub, PeerPublicKey: n.bPub, Key: endpoint.Key(n.aPub, n.bPub), Value: value}
}

func (n *node) getReq() pluginapi.PluginRequest {
	return pluginapi.PluginRequest{Device: "wgmesh", LocalPublicKey: n.aPub, PeerPublicKey: n.bPub, Key: endpoint.Key(n.bPub, n.aPub)}
}

// publishOwn stores our record, which tells the store our public IP.
func (n *node) publishOwn(t *testing.T, host string) {
	t.Helper()
	if err := n.store.Set(context.Background(), n.setReq(seal(t, `{"ipv4":"`+host+`:51820"}`, n.bPub, n.aPriv))); err != nil {
		t.Fatal(err)
	}
}

func (n *node) browseSees(lan string) {
	pk := base64.StdEncoding.EncodeToString(n.bPub[:])
	host, port, _ := strings.Cut(lan, ":")
	n.browse = `=;eth0;IPv4;stunmesh\032b\032wgmesh;_wgmesh._udp;local;b.local;` + host + `;` + port + `;"pk=` + pk + `"`
}

func TestSetPassesThroughAndAdvertises(t *testing.T) {
	n := newNode(t)
	n.publishOwn(t, "198.51.100.1")
	if n.backend.sets != 1 {
		t.Fatalf("backend sets = %d, want 1", n.backend.sets)
	}
	pk := base64.StdEncoding.EncodeToString(n.aPub[:])
	if !strings.Contains(n.service, "<txt-record>pk="+pk+"</txt-record>") || !strings.Contains(n.service, "<port>51820</port>") {
		t.Errorf("service file:\n%s", n.service)
	}
}

func TestGetPeerElsewhereReturnsBackendRecord(t *testing.T) {
	n := newNode(t)
	n.publishOwn(t, "198.51.100.1")
	rec := seal(t, `{"ipv4":"203.0.113.9:51820"}`, n.aPub, n.bPriv)
	n.backend.data[n.getReq().Key] = rec
	n.browseSees("192.0.2.20:51820")

	got, err := n.store.Get(context.Background(), n.getReq())
	if err != nil || got != rec {
		t.Fatalf("got %q, %v; want backend record", got, err)
	}
	if n.browses != 0 {
		t.Error("browsed avahi for a peer behind another public IP")
	}
}

func TestGetSamePublicIPReturnsLAN(t *testing.T) {
	n := newNode(t)
	n.publishOwn(t, "198.51.100.1")
	n.backend.data[n.getReq().Key] = seal(t, `{"ipv4":"198.51.100.1:51821"}`, n.aPub, n.bPriv)
	n.browseSees("192.0.2.20:51820")

	got, err := n.store.Get(context.Background(), n.getReq())
	if err != nil {
		t.Fatal(err)
	}
	// stunmesh on node a opens the answer with (b pub, a priv).
	if msg := open(t, got, n.bPub, n.aPriv); msg != `{"ipv4":"192.0.2.20:51820"}` {
		t.Errorf("answer opens to %s", msg)
	}
}

func TestGetSamePublicIPWithoutMDNSReturnsBackendRecord(t *testing.T) {
	n := newNode(t)
	n.publishOwn(t, "198.51.100.1")
	rec := seal(t, `{"ipv4":"198.51.100.1:51821"}`, n.aPub, n.bPriv)
	n.backend.data[n.getReq().Key] = rec

	if got, err := n.store.Get(context.Background(), n.getReq()); err != nil || got != rec {
		t.Fatalf("got %q, %v; want backend record", got, err)
	}
}

func TestGetBackendFailureFallsBackToLAN(t *testing.T) {
	n := newNode(t)
	n.backend.getErr = errors.New("proxy down")
	n.browseSees("192.0.2.20:51820")

	got, err := n.store.Get(context.Background(), n.getReq())
	if err != nil {
		t.Fatal(err)
	}
	if msg := open(t, got, n.bPub, n.aPriv); msg != `{"ipv4":"192.0.2.20:51820"}` {
		t.Errorf("answer opens to %s", msg)
	}
}

func TestGetBackendFailureWithoutLANReturnsError(t *testing.T) {
	n := newNode(t)
	n.backend.getErr = errors.New("proxy down")
	if _, err := n.store.Get(context.Background(), n.getReq()); err == nil {
		t.Fatal("want backend error")
	}
}

func TestUnknownPeerPassesThrough(t *testing.T) {
	n := newNode(t)
	stranger := pluginapi.PluginRequest{Device: "wgmesh", PeerPublicKey: pluginapi.Key{9}, Key: "eeee", Value: "y"}
	if err := n.store.Set(context.Background(), stranger); err != nil || n.backend.data["eeee"] != "y" {
		t.Errorf("set not passed through: %v", err)
	}
	if got, err := n.store.Get(context.Background(), stranger); err != nil || got != "y" {
		t.Errorf("get not passed through: %q, %v", got, err)
	}
	if n.service != "" || n.browses != 0 {
		t.Error("unknown peer touched avahi")
	}
}

func TestGetEmptyRecordFallsBackToLAN(t *testing.T) {
	n := newNode(t)
	n.backend.data[n.getReq().Key] = "" // the Store contract's "nothing stored"
	n.browseSees("192.0.2.20:51820")

	got, err := n.store.Get(context.Background(), n.getReq())
	if err != nil {
		t.Fatal(err)
	}
	if msg := open(t, got, n.bPub, n.aPriv); msg != `{"ipv4":"192.0.2.20:51820"}` {
		t.Errorf("answer opens to %s", msg)
	}
}

func TestFindLANEndpoint(t *testing.T) {
	peer := [32]byte{7}
	pk := base64.StdEncoding.EncodeToString(peer[:])
	browse := strings.Join([]string{
		`+;eth0;IPv4;stunmesh\032node-b\032wgmesh;_wgmesh._udp;local`,
		`=;lo;IPv4;stunmesh\032node-a\032wgmesh;_wgmesh._udp;local;node-a.local;127.0.0.1;51820;"pk=` + pk + `"`,
		`=;eth0;IPv6;stunmesh\032node-b\032wgmesh;_wgmesh._udp;local;node-b.local;fe80::1;51820;"pk=` + pk + `"`,
		`=;eth0;IPv4;stunmesh\032node-c\032wgmesh;_wgmesh._udp;local;node-c.local;192.0.2.30;51820;"pk=other"`,
		`=;eth0;IPv4;stunmesh\032node-b\032wgmesh;_wgmesh._udp;local;node-b.local;192.0.2.20;51820;"pk=` + pk + `"`,
		`malformed`,
	}, "\n")
	if got := findLANEndpoint(browse, peer); got != "192.0.2.20:51820" {
		t.Errorf("got %q", got)
	}
	if got := findLANEndpoint("", peer); got != "" {
		t.Errorf("empty browse gave %q", got)
	}
}
