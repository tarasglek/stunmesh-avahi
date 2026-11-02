// SPDX-License-Identifier: LGPL-3.0-or-later

// Package wgdev reads what plugins need from a WireGuard device that the
// core's PluginRequest does not carry: the private key, to open and seal
// records with pluginapi/endpoint, and each peer's live state. As the
// maintainer suggested on stunmesh-go #320, a plugin reads the private key
// itself; an in-process plugin runs as root anyway.
package wgdev

import (
	"time"

	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey     [32]byte
	Endpoint      string // host:port WireGuard currently sends to, "" if none
	LastHandshake time.Time
	Keepalive     time.Duration // persistent keepalive interval, 0 if off
	Bytes         int64         // received plus transmitted
}

type Device struct {
	PrivateKey, PublicKey [32]byte
	ListenPort            int
	Peers                 []Peer
}

// Read returns the named device's keys and peers. It asks the kernel over
// netlink on every call.
func Read(name string) (Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return Device{}, err
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil {
		return Device{}, err
	}
	// wgtypes.Key is a [32]byte, so it assigns to our unnamed [32]byte fields.
	dev := Device{PrivateKey: d.PrivateKey, PublicKey: d.PublicKey, ListenPort: d.ListenPort}
	for _, p := range d.Peers {
		peer := Peer{PublicKey: p.PublicKey, LastHandshake: p.LastHandshakeTime, Keepalive: p.PersistentKeepaliveInterval, Bytes: p.ReceiveBytes + p.TransmitBytes}
		if p.Endpoint != nil {
			peer.Endpoint = p.Endpoint.String()
		}
		dev.Peers = append(dev.Peers, peer)
	}
	return dev, nil
}

// Lookup reads the request's device with read and finds the request's peer
// on it. It is false when the request names no device or peer, the device
// cannot be read, or the peer is not on it: the call is not ours to handle.
func Lookup(read func(string) (Device, error), req pluginapi.PluginRequest) (Device, Peer, bool) {
	if req.Device == "" || req.PeerPublicKey == (pluginapi.Key{}) {
		return Device{}, Peer{}, false
	}
	d, err := read(req.Device)
	if err != nil {
		return Device{}, Peer{}, false
	}
	for _, p := range d.Peers {
		if p.PublicKey == req.PeerPublicKey {
			return d, p, true
		}
	}
	return Device{}, Peer{}, false
}

// SetKeepalive sets one peer's persistent keepalive interval, 0 to turn it
// off, leaving the rest of the device as it is.
func SetKeepalive(name string, peer [32]byte, interval time.Duration) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:                   peer,
		UpdateOnly:                  true,
		PersistentKeepaliveInterval: &interval,
	}}})
}
