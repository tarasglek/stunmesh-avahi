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

const serviceType = "_wgmesh._udp"

var (
	servicesDir = "/etc/avahi/services"
	stateDir    = "/run/stunmesh-avahi"
)

type wgDevice struct {
	privateKey, publicKey [32]byte
	listenPort            string
	peers                 [][32]byte
}

// request is one stunmesh shell-protocol call.
type request struct{ action, key, value string }

// call is a request resolved to our device and the peer it is about.
type call struct {
	devName    string
	dev        wgDevice
	peer       [32]byte
	req        request
	backendCmd []string
	raw        []byte
}

func warn(f string, a ...any) { fmt.Fprintf(os.Stderr, "stunmesh-avahi: "+f+"\n", a...) }

func parseRequest(raw []byte) request {
	f := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			f[k] = v
		}
	}
	return request{f["STUNMESH_ACTION"], f["STUNMESH_KEY"], f["STUNMESH_VALUE"]}
}

func decodeWGKey(s string) (k [32]byte, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) != 32 {
		err = errors.New("key is not 32 bytes")
	}
	copy(k[:], b)
	return k, err
}

// parseWGDump reads `wg show DEV dump`: the device line, then one line per peer.
func parseWGDump(dump string) (dev wgDevice, err error) {
	for i, line := range strings.Split(strings.TrimSpace(dump), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			return dev, fmt.Errorf("short wg dump line %d", i+1)
		}
		if i == 0 {
			if dev.privateKey, err = decodeWGKey(f[0]); err == nil {
				dev.publicKey, err = decodeWGKey(f[1])
			}
			dev.listenPort = f[2]
		} else {
			var p [32]byte
			p, err = decodeWGKey(f[0])
			dev.peers = append(dev.peers, p)
		}
		if err != nil {
			return dev, err
		}
	}
	return dev, nil
}

// recordKey is stunmesh's store key for records from sender to receiver.
func recordKey(sender, receiver [32]byte) string {
	sum := sha1.Sum(append(sender[:], receiver[:]...))
	return hex.EncodeToString(sum[:])
}

// peerForKey finds the peer a request is about: set stores our record for
// the peer, get fetches the peer's record for us.
func peerForKey(dev wgDevice, req request) (p [32]byte, ok bool) {
	for _, p := range dev.peers {
		if (req.action == "set" && recordKey(dev.publicKey, p) == req.key) ||
			(req.action == "get" && recordKey(p, dev.publicKey) == req.key) {
			return p, true
		}
	}
	return p, false
}

func lookupPeer(devName string, req request) (dev wgDevice, peer [32]byte, err error) {
	dump, err := exec.Command("wg", "show", devName, "dump").Output()
	if err == nil {
		dev, err = parseWGDump(string(dump))
	}
	if err != nil {
		return dev, peer, err
	}
	peer, ok := peerForKey(dev, req)
	if !ok {
		return dev, peer, fmt.Errorf("no %s peer for key %s", devName, req.key)
	}
	return dev, peer, nil
}

// recordPublicHost returns the IPv4 host in a record exchanged with peer, or
// "" if it does not open. Records in both directions open with the same key.
func recordPublicHost(dev wgDevice, peer [32]byte, record string) string {
	raw, err := hex.DecodeString(record)
	if err != nil || len(raw) < 24 {
		return ""
	}
	nonce := [24]byte(raw[:24])
	msg, ok := box.Open(nil, raw[24:], &nonce, &peer, &dev.privateKey)
	var ep struct {
		IPv4 string `json:"ipv4"`
	}
	if !ok || json.Unmarshal(msg, &ep) != nil {
		return ""
	}
	host, _, _ := net.SplitHostPort(ep.IPv4)
	return host
}

// sealEndpoint makes a record that opens like one the peer published.
func sealEndpoint(dev wgDevice, peer [32]byte, endpoint string) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	msg, _ := json.Marshal(map[string]string{"ipv4": endpoint})
	return hex.EncodeToString(box.Seal(nonce[:], msg, &nonce, &peer, &dev.privateKey)), nil
}

func samePublicIP(peerHost, ourHost string) bool { return peerHost != "" && peerHost == ourHost }

func avahiServiceXML(devName string, dev wgDevice) string {
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
`, devName, serviceType, dev.listenPort, base64.StdEncoding.EncodeToString(dev.publicKey[:]))
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

func avahiBrowse() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func saveOurHost(devName, host string) {
	if host == "" {
		return
	}
	err := os.MkdirAll(stateDir, 0o700)
	if err == nil {
		err = os.WriteFile(filepath.Join(stateDir, devName), []byte(host), 0o600)
	}
	if err != nil {
		warn("state: %v", err)
	}
}

func loadOurHost(devName string) string {
	b, _ := os.ReadFile(filepath.Join(stateDir, devName))
	return string(b)
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

func (c call) backend() *exec.Cmd {
	cmd := exec.Command(c.backendCmd[0], c.backendCmd[1:]...)
	cmd.Stdin, cmd.Stderr = bytes.NewReader(c.raw), os.Stderr
	return cmd
}

func (c call) passThrough() int {
	cmd := c.backend()
	cmd.Stdout = os.Stdout
	return exitCode(cmd.Run())
}

func (c call) set() int {
	path := filepath.Join(servicesDir, "stunmesh-"+c.devName+".service")
	if err := writeIfChanged(path, avahiServiceXML(c.devName, c.dev)); err != nil {
		warn("avahi service: %v", err) // LAN discovery is optional; still publish
	}
	saveOurHost(c.devName, recordPublicHost(c.dev, c.peer, c.req.value))
	return c.passThrough()
}

func (c call) get() int {
	out, err := c.backend().Output()
	record := strings.TrimSpace(string(out))
	if answer, ok := c.lanAnswer(record, err); ok {
		fmt.Println(answer)
		return 0
	}
	if err != nil {
		return exitCode(err)
	}
	fmt.Println(record)
	return 0
}

// lanAnswer returns a sealed LAN endpoint when the peer is behind our public
// IP (or the backend failed) and avahi sees it.
func (c call) lanAnswer(record string, backendErr error) (string, bool) {
	if backendErr == nil && !samePublicIP(recordPublicHost(c.dev, c.peer, record), loadOurHost(c.devName)) {
		return "", false // peer is elsewhere: stale mDNS must not win
	}
	endpoint := findLANEndpoint(avahiBrowse(), c.peer)
	if endpoint == "" {
		return "", false
	}
	sealed, err := sealEndpoint(c.dev, c.peer, endpoint)
	return sealed, err == nil
}

func run(devName string, backendCmd []string, raw []byte) int {
	c := call{devName: devName, req: parseRequest(raw), backendCmd: backendCmd, raw: raw}
	var err error
	if c.dev, c.peer, err = lookupPeer(devName, c.req); err != nil {
		warn("%s: %v, passing through", c.req.action, err)
		return c.passThrough()
	}
	if c.req.action == "set" {
		return c.set()
	}
	return c.get() // lookupPeer only matches set and get
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
