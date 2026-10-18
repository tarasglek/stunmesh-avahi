// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func keypair(t *testing.T) (pub, priv [32]byte) {
	t.Helper()
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return *p, *s
}

// stunmeshSeal mirrors stunmesh-go internal/crypto/endpoint.go Encrypt.
func stunmeshSeal(t *testing.T, msg string, peerPub, priv [32]byte) string {
	t.Helper()
	var nonce [24]byte
	rand.Read(nonce[:])
	return hex.EncodeToString(box.Seal(nonce[:], []byte(msg), &nonce, &peerPub, &priv))
}

// stunmeshOpen mirrors stunmesh-go internal/crypto/endpoint.go Decrypt.
func stunmeshOpen(t *testing.T, record string, peerPub, priv [32]byte) string {
	t.Helper()
	data, err := hex.DecodeString(record)
	if err != nil || len(data) < 24 {
		t.Fatalf("bad record %q", record)
	}
	nonce := [24]byte(data[:24])
	msg, ok := box.Open(nil, data[24:], &nonce, &peerPub, &priv)
	if !ok {
		t.Fatal("record does not open")
	}
	return string(msg)
}

func TestRecordKeyMatchesStunmesh(t *testing.T) {
	// Vectors from stunmesh-go internal/entity/peer_id_test.go.
	own, peer := [32]byte{0}, [32]byte{1}
	if got := recordKey(own, peer); got != "37b7dcf21e0e183a9a86170997df242a84a85ff7" {
		t.Errorf("set key %s", got)
	}
	if got := recordKey(peer, own); got != "9c8d8e5a31c9802b093c4116dfb0a23a311b8029" {
		t.Errorf("get key %s", got)
	}
}

func TestPeerFor(t *testing.T) {
	own, other, peer := [32]byte{0}, [32]byte{2}, [32]byte{1}
	d := wgDevice{publicKey: own, peers: [][32]byte{other, peer}}
	if p, ok := peerForKey(d, request{action: "set", key: recordKey(own, peer)}); !ok || p != peer {
		t.Error("set key not mapped to peer")
	}
	if p, ok := peerForKey(d, request{action: "get", key: recordKey(peer, own)}); !ok || p != peer {
		t.Error("get key not mapped to peer")
	}
	if _, ok := peerForKey(d, request{action: "get", key: recordKey(own, peer)}); ok {
		t.Error("set key accepted for get")
	}
}

func TestParseDump(t *testing.T) {
	aPub, aPriv := keypair(t)
	bPub, _ := keypair(t)
	b64 := func(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }
	dump := b64(aPriv) + "\t" + b64(aPub) + "\t51820\toff\n" +
		b64(bPub) + "\t(none)\t192.0.2.20:51820\t10.0.0.2/32\t0\t0\t0\t25\n"
	d, err := parseWGDump(dump)
	if err != nil || d.privateKey != aPriv || d.publicKey != aPub || d.listenPort != "51820" || len(d.peers) != 1 || d.peers[0] != bPub {
		t.Fatalf("got %+v, %v", d, err)
	}
	if _, err := parseWGDump("garbage"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestRecordPublicHostBothDirections(t *testing.T) {
	aPub, aPriv := keypair(t)
	bPub, bPriv := keypair(t)
	a := wgDevice{privateKey: aPriv, publicKey: aPub}
	// What node a publishes for b (set), and what b publishes for a (get).
	sent := stunmeshSeal(t, `{"ipv4":"198.51.100.1:51820"}`, bPub, aPriv)
	received := stunmeshSeal(t, `{"ipv4":"198.51.100.1:51821"}`, aPub, bPriv)
	if h := recordPublicHost(a, bPub, sent); h != "198.51.100.1" {
		t.Errorf("own record: %q", h)
	}
	if h := recordPublicHost(a, bPub, received); h != "198.51.100.1" {
		t.Errorf("peer record: %q", h)
	}
}

func TestRecordPublicHostGarbage(t *testing.T) {
	aPub, aPriv := keypair(t)
	bPub, _ := keypair(t)
	cPub, cPriv := keypair(t)
	a := wgDevice{privateKey: aPriv, publicKey: aPub}
	for _, rec := range []string{"", "zz", "00", stunmeshSeal(t, `{"ipv4":"x"}`, cPub, cPriv), stunmeshSeal(t, `not json`, bPub, aPriv)} {
		if h := recordPublicHost(a, bPub, rec); h != "" {
			t.Errorf("%q opened to %q", rec, h)
		}
	}
}

func TestSealOpensInStunmesh(t *testing.T) {
	aPub, aPriv := keypair(t)
	bPub, bPriv := keypair(t)
	rec, err := sealEndpoint(wgDevice{privateKey: aPriv, publicKey: aPub}, bPub, "192.0.2.20:51820")
	if err != nil {
		t.Fatal(err)
	}
	// Node a's own stunmesh opens records from b with (b pub, a priv).
	if got := stunmeshOpen(t, rec, bPub, aPriv); got != `{"ipv4":"192.0.2.20:51820"}` {
		t.Errorf("a opens %s", got)
	}
	// Indistinguishable from a record b sealed for a.
	if got := stunmeshOpen(t, rec, aPub, bPriv); got != `{"ipv4":"192.0.2.20:51820"}` {
		t.Errorf("b opens %s", got)
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

func TestSamePublicIP(t *testing.T) {
	if !samePublicIP("198.51.100.1", "198.51.100.1") {
		t.Error("same IP")
	}
	for _, c := range [][2]string{{"198.51.100.1", "203.0.113.9"}, {"", "198.51.100.1"}, {"198.51.100.1", ""}, {"", ""}} {
		if samePublicIP(c[0], c[1]) {
			t.Errorf("samePublicIP(%q, %q)", c[0], c[1])
		}
	}
}

func TestLanAnswerSkipsPeerElsewhere(t *testing.T) {
	aPub, aPriv := keypair(t)
	bPub, bPriv := keypair(t)
	defer func(d string) { stateDir = d }(stateDir)
	stateDir = t.TempDir()
	saveOurHost("wgmesh", "198.51.100.1")
	record := stunmeshSeal(t, `{"ipv4":"203.0.113.9:51820"}`, aPub, bPriv)
	c := call{devName: "wgmesh", dev: wgDevice{privateKey: aPriv, publicKey: aPub}, peer: bPub}
	// Returns before browsing avahi, so stale mDNS can't override the store.
	if _, ok := c.lanAnswer(record, nil); ok {
		t.Error("LAN answer for a peer behind another public IP")
	}
}

func TestWriteIfChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.service")
	if err := writeIfChanged(path, "a"); err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(path)
	os.Chtimes(path, st1.ModTime().Add(-3600e9), st1.ModTime().Add(-3600e9))
	st1, _ = os.Stat(path)
	writeIfChanged(path, "a")
	if st2, _ := os.Stat(path); !st2.ModTime().Equal(st1.ModTime()) {
		t.Error("unchanged contents rewritten")
	}
	writeIfChanged(path, "b")
	if b, _ := os.ReadFile(path); string(b) != "b" {
		t.Errorf("got %q", b)
	}
}
