// SPDX-License-Identifier: LGPL-3.0-or-later

package wgdev

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ParseUAPI reads a device from WireGuard's UAPI get format, the text
// wireguard-go's Device.IpcGet returns, for devices that live in a process
// rather than the kernel. The format carries no interface public key, so it
// is derived from the private key, as wgctrl does.
func ParseUAPI(s string) (Device, error) {
	var d Device
	var peer *Peer
	var sec, nsec int64
	endPeer := func() {
		if peer != nil && (sec != 0 || nsec != 0) {
			peer.LastHandshake = time.Unix(sec, nsec)
		}
		sec, nsec = 0, 0
	}
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Device{}, fmt.Errorf("uapi: malformed line %q", line)
		}
		var err error
		switch k {
		case "errno":
			if v != "0" {
				return Device{}, fmt.Errorf("uapi: errno %s", v)
			}
		case "private_key":
			err = parseKey(v, &d.PrivateKey)
			if err == nil {
				var pub []byte
				pub, err = curve25519.X25519(d.PrivateKey[:], curve25519.Basepoint)
				copy(d.PublicKey[:], pub)
			}
		case "listen_port":
			d.ListenPort, err = strconv.Atoi(v)
		case "public_key":
			endPeer()
			d.Peers = append(d.Peers, Peer{})
			peer = &d.Peers[len(d.Peers)-1]
			err = parseKey(v, &peer.PublicKey)
		default:
			if peer != nil {
				err = parsePeerField(peer, k, v, &sec, &nsec)
			}
		}
		if err != nil {
			return Device{}, fmt.Errorf("uapi: %s: %w", k, err)
		}
	}
	endPeer()
	return d, nil
}

func parsePeerField(p *Peer, k, v string, sec, nsec *int64) error {
	var err error
	var n int64
	switch k {
	case "endpoint":
		p.Endpoint = v
	case "last_handshake_time_sec":
		*sec, err = strconv.ParseInt(v, 10, 64)
	case "last_handshake_time_nsec":
		*nsec, err = strconv.ParseInt(v, 10, 64)
	case "persistent_keepalive_interval":
		n, err = strconv.ParseInt(v, 10, 64)
		p.Keepalive = time.Duration(n) * time.Second
	case "rx_bytes", "tx_bytes":
		n, err = strconv.ParseInt(v, 10, 64)
		p.Bytes += n
	}
	return err
}

func parseKey(v string, k *[32]byte) error {
	b, err := hex.DecodeString(v)
	if err != nil {
		return err
	}
	if len(b) != len(k) {
		return fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return nil
}
