// SPDX-License-Identifier: LGPL-3.0-or-later

// stunmesh-avahi is a stunmesh-go shell plugin that wraps another shell
// plugin. It advertises the WireGuard device over mDNS (an avahi static
// service), and when a peer shares our public IPv4 and is visible over mDNS,
// answers get with the peer's LAN address instead of its public one.
// Everything else is passed to the backend plugin unchanged, so it makes the
// same backend calls as using the backend directly.
//
//	stunmesh-avahi -dev wgmesh -- stunmesh-opendht-shell -endpoint URL
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const svcType = "_wgmesh._udp"

var (
	servicesDir = "/etc/avahi/services"
	stateDir    = "/run/stunmesh-avahi"
)

type device struct {
	priv, pub [32]byte
	port      string
	peers     [][32]byte
}

func warn(f string, a ...any) { fmt.Fprintf(os.Stderr, "stunmesh-avahi: "+f+"\n", a...) }

func decodeKey(s string) (k [32]byte, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) != 32 {
		err = errors.New("key is not 32 bytes")
	}
	copy(k[:], b)
	return k, err
}

// parseDump reads `wg show DEV dump`: the device line, then one line per peer.
func parseDump(out string) (d device, err error) {
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			return d, fmt.Errorf("short wg dump line %d", i+1)
		}
		if i == 0 {
			if d.priv, err = decodeKey(f[0]); err == nil {
				d.pub, err = decodeKey(f[1])
			}
			d.port = f[2]
		} else {
			var p [32]byte
			p, err = decodeKey(f[0])
			d.peers = append(d.peers, p)
		}
		if err != nil {
			return d, err
		}
	}
	return d, nil
}

// storeKey is stunmesh's key for records sent from one key to another.
func storeKey(from, to [32]byte) string {
	sum := sha1.Sum(append(from[:], to[:]...))
	return hex.EncodeToString(sum[:])
}

// peerFor finds the peer a request is about: set stores our record for the
// peer, get fetches the peer's record for us.
func peerFor(d device, action, key string) (p [32]byte, ok bool) {
	for _, p := range d.peers {
		if (action == "set" && storeKey(d.pub, p) == key) || (action == "get" && storeKey(p, d.pub) == key) {
			return p, true
		}
	}
	return p, false
}

// openHost returns the IPv4 host in a stunmesh record exchanged with peer, or
// "" if it does not open. Records in both directions open with the same key.
func openHost(d device, peer [32]byte, record string) string {
	raw, err := hex.DecodeString(record)
	if err != nil || len(raw) < 24 {
		return ""
	}
	nonce := [24]byte(raw[:24])
	msg, ok := box.Open(nil, raw[24:], &nonce, &peer, &d.priv)
	var ep struct {
		IPv4 string `json:"ipv4"`
	}
	if !ok || json.Unmarshal(msg, &ep) != nil {
		return ""
	}
	host, _, _ := net.SplitHostPort(ep.IPv4)
	return host
}

// seal makes a record that opens like one the peer published.
func seal(d device, peer [32]byte, endpoint string) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	msg, _ := json.Marshal(map[string]string{"ipv4": endpoint})
	return hex.EncodeToString(box.Seal(nonce[:], msg, &nonce, &peer, &d.priv)), nil
}

func serviceXML(dev string, d device) string {
	return fmt.Sprintf(`<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">stunmesh %%h %s</name>
  <service>
    <type>%s</type>
    <port>%s</port>
    <txt-record>pk=%s</txt-record>
  </service>
</service-group>
`, dev, svcType, d.port, base64.StdEncoding.EncodeToString(d.pub[:]))
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

// lanEndpoint finds the peer's IPv4 ip:port in `avahi-browse -rpt` output.
func lanEndpoint(browse string, peer [32]byte) string {
	txt := `"pk=` + base64.StdEncoding.EncodeToString(peer[:]) + `"`
	for _, line := range strings.Split(browse, "\n") {
		f := strings.Split(line, ";")
		if len(f) >= 10 && f[0] == "=" && f[1] != "lo" && f[2] == "IPv4" && strings.Contains(f[9], txt) {
			return net.JoinHostPort(f[7], f[8])
		}
	}
	return ""
}

func browse() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "avahi-browse", "-rptk", svcType).Output()
	return string(out)
}

// useLAN reports whether get should answer with the LAN address: the backend
// record shows the peer behind our public IP, or the backend failed.
func useLAN(backendOK bool, peerHost, ourHost string) bool {
	return !backendOK || (peerHost != "" && peerHost == ourHost)
}

func run(dev string, backend []string, in []byte) int {
	vars := map[string]string{}
	for _, line := range strings.Split(string(in), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			vars[k] = v
		}
	}
	action := vars["STUNMESH_ACTION"]
	cmd := exec.Command(backend[0], backend[1:]...)
	cmd.Stdin, cmd.Stderr = bytes.NewReader(in), os.Stderr

	var d device
	out, err := exec.Command("wg", "show", dev, "dump").Output()
	if err == nil {
		d, err = parseDump(string(out))
	}
	peer, known := peerFor(d, action, vars["STUNMESH_KEY"])
	if err != nil || !known {
		warn("%s: not a known peer of %s (%v), passing through", action, dev, err)
		cmd.Stdout = os.Stdout
		return exitCode(cmd.Run())
	}
	state := filepath.Join(stateDir, dev)

	if action == "set" {
		if err := writeIfChanged(filepath.Join(servicesDir, "stunmesh-"+dev+".service"), serviceXML(dev, d)); err != nil {
			warn("avahi service: %v", err)
		}
		if host := openHost(d, peer, vars["STUNMESH_VALUE"]); host != "" {
			if err := os.MkdirAll(stateDir, 0o700); err == nil {
				err = os.WriteFile(state, []byte(host), 0o600)
			}
		}
		cmd.Stdout = os.Stdout
		return exitCode(cmd.Run())
	}

	out, err = cmd.Output()
	record := strings.TrimSpace(string(out))
	ours, _ := os.ReadFile(state)
	if useLAN(err == nil, openHost(d, peer, record), string(ours)) {
		if lan := lanEndpoint(browse(), peer); lan != "" {
			if sealed, serr := seal(d, peer, lan); serr == nil {
				fmt.Println(sealed)
				return 0
			}
		}
	}
	if err != nil {
		return exitCode(err)
	}
	fmt.Println(record)
	return 0
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		warn("%v", err)
		return 1
	}
	return 0
}

func main() {
	dev := flag.String("dev", "", "WireGuard device")
	flag.Parse()
	if *dev == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: stunmesh-avahi -dev DEV -- BACKEND [ARGS...]")
		os.Exit(2)
	}
	var in bytes.Buffer
	if _, err := in.ReadFrom(os.Stdin); err != nil {
		warn("stdin: %v", err)
		os.Exit(1)
	}
	os.Exit(run(*dev, flag.Args(), in.Bytes()))
}
