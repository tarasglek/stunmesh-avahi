// SPDX-License-Identifier: LGPL-3.0-or-later

package wgdev

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func hexKey(fill byte) string { return strings.Repeat(hex.EncodeToString([]byte{fill}), 32) }

func key(fill byte) (k [32]byte) {
	for i := range k {
		k[i] = fill
	}
	return k
}

// A wireguard-go IpcGet dump: one peer with traffic, one never seen.
var uapiFixture = "private_key=" + hexKey(0x41) + `
listen_port=51820
public_key=` + hexKey(0x02) + `
preshared_key=` + hexKey(0) + `
protocol_version=1
endpoint=203.0.113.40:51823
last_handshake_time_sec=1793694725
last_handshake_time_nsec=1813980
tx_bytes=212
rx_bytes=92
persistent_keepalive_interval=25
allowed_ip=10.200.0.5/32
public_key=` + hexKey(0x03) + `
preshared_key=` + hexKey(0) + `
protocol_version=1
last_handshake_time_sec=0
last_handshake_time_nsec=0
tx_bytes=0
rx_bytes=0
persistent_keepalive_interval=0
allowed_ip=10.200.0.6/32
errno=0
`

func TestParseUAPI(t *testing.T) {
	d, err := ParseUAPI(uapiFixture)
	if err != nil {
		t.Fatal(err)
	}
	priv := key(0x41)
	pub, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	if d.PrivateKey != priv || string(d.PublicKey[:]) != string(pub) || d.ListenPort != 51820 {
		t.Errorf("interface = %x %x %d", d.PrivateKey, d.PublicKey, d.ListenPort)
	}
	if len(d.Peers) != 2 {
		t.Fatalf("peers = %+v", d.Peers)
	}
	want := Peer{PublicKey: key(2), Endpoint: "203.0.113.40:51823", LastHandshake: time.Unix(1793694725, 1813980), Keepalive: 25 * time.Second, Bytes: 304}
	if p := d.Peers[0]; p != want {
		t.Errorf("peer 0 = %+v, want %+v", p, want)
	}
	// No handshake is the zero time, as wgctrl reports it, not the epoch.
	if p := d.Peers[1]; p != (Peer{PublicKey: key(3)}) {
		t.Errorf("peer 1 = %+v", p)
	}
}

func TestParseUAPIErrors(t *testing.T) {
	for name, s := range map[string]string{
		"errno":     "errno=1\n",
		"no equals": "private_key\n",
		"short key": "public_key=0102\n",
		"bad hex":   "private_key=" + strings.Repeat("zz", 32) + "\n",
		"bad port":  "listen_port=x\n",
		"bad bytes": "public_key=" + hexKey(2) + "\nrx_bytes=x\n",
	} {
		if _, err := ParseUAPI(s); err == nil {
			t.Errorf("%s: accepted %q", name, s)
		}
	}
}
