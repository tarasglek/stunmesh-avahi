// SPDX-License-Identifier: LGPL-3.0-or-later

package wgdev

import (
	"testing"
	"time"
)

type fakeBackend struct {
	dev  Device
	peer [32]byte
	set  time.Duration
}

func (f *fakeBackend) Read() (Device, error) { return f.dev, nil }
func (f *fakeBackend) SetKeepalive(peer [32]byte, d time.Duration) error {
	f.peer, f.set = peer, d
	return nil
}

// A registered device is served by its backend, never by netlink, and only
// until it is unregistered.
func TestRegister(t *testing.T) {
	const name = "wgdev-test0"
	f := &fakeBackend{dev: Device{ListenPort: 51820}}
	unregister, err := Register(name, f)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := Read(name); err != nil || d.ListenPort != 51820 {
		t.Errorf("Read = %+v, %v", d, err)
	}
	if err := SetKeepalive(name, key(2), 25*time.Second); err != nil || f.peer != key(2) || f.set != 25*time.Second {
		t.Errorf("SetKeepalive reached backend as %x %v, err %v", f.peer, f.set, err)
	}
	if _, err := Register(name, f); err == nil {
		t.Error("second Register of one name accepted")
	}

	unregister()
	unregister() // idempotent
	// Any error means the backend no longer answers: the kernel has no such
	// device, or netlink is refused to this process. Do not tighten this to
	// one error string; which one depends on the host.
	if _, err := Read(name); err == nil {
		t.Error("Read after unregister still answered")
	}
	again, err := Register(name, f)
	if err != nil {
		t.Fatalf("Register after unregister: %v", err)
	}
	again()
}
