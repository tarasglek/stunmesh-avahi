# stunmesh-avahi

Two [stunmesh-go](https://github.com/tjjh89017/stunmesh-go) plugins, and a
stunmesh-go binary with them compiled in, for a WireGuard mesh that costs
next to nothing on metered links and works between peers on the same LAN.

- **avahi**: stunmesh only publishes each node's public ip:port, so two
  nodes behind the same router try to reach each other through its public
  IP, which fails unless the router hairpins UDP. avahi advertises the
  WireGuard device over mDNS and, when a peer shares our public IP and is
  visible on the LAN, answers with its LAN ip:port instead.
- **lease**: publishes our record only when it changes or before the DHT
  expires it, skips lookups of peers with a fresh WireGuard handshake, and
  quiets peers that are away: their lookups back off to every 4 minutes
  and, with `keepalive` set, their WireGuard keepalive is off until they
  return. With `keepalive` set it also watches away peers on the OpenDHT
  proxies and restores keepalive as soon as one republishes, so a waking
  peer is not shut out by our NAT until our next lookup.

Both wrap another plugin instance through stunmesh-go's public plugin API
([#320](https://github.com/tjjh89017/stunmesh-go/issues/320)), so they work
with any store, not only OpenDHT.

## Config

```yaml
interfaces:
  wgmesh:
    peers:
      node-b:
        public_key: "<wg-pubkey-of-node-b>"
        plugin: mesh
plugins:
  dht:
    type: builtin
    name: opendht
    endpoints: ["http://dhtproxy2.jami.net", "http://dhtproxy3.jami.net", "https://dhtproxy2.jami.net"]
  leased:
    type: builtin
    name: lease
    next: dht
    keepalive: 25s   # the WireGuard config's persistent keepalive; omit to leave keepalives alone
  mesh:
    type: builtin
    name: avahi
    next: leased
```

lease republishes every 7m30s, so keep stunmesh's `refresh_interval` at 2
minutes or less against OpenDHT's 10 minute expiry.

avahi writes `/etc/avahi/services/stunmesh-<device>.service`, only when the
port or key changes.

## Measured

One node with 6 peers, one of them offline:

| Setup | DHT per day | WireGuard to the offline peer per day |
|---|---|---|
| shell plugins, https | ~196 MB | ~2.1 MB |
| avahi, lease, opendht, https | ~7.5 MB | ~2.1 MB |
| same, plain http | ~2.4 MB | ~2.1 MB |
| same, with `keepalive` | ~1.3 MB | 0 |

## Build and run

```sh
make check   # build for this host, run the tests and a plugin-chain smoke test
make dist    # release bundles for ARCHES (amd64 arm64) in dist/
```

`cmd/stunmesh-go` is upstream's `main.go` importing `builtin/opendht` and
these plugins; see upstream's
[Custom Binaries and Go Plugins](https://docs.stunmesh.dev/plugins/custom-binary/)
for how that works. `go.mod` pins stunmesh-go, `GO_VERSION` the toolchain;
the same commit gives byte-identical bundles.

Each bundle, `stunmesh-bundle-linux-<arch>-<version>.tar.gz`, holds the
binary, a config generator, installers and service units for systemd and
OpenWrt nodes, and no site config. See [deploy/README.md](deploy/README.md).

Release: tag, push the tag, `make release`.

## Limits

- IPv4 only: live and LAN answers are IPv4 records.
- No multicast (guest Wi-Fi, client isolation): avahi falls back to the
  store's record.
- A waking peer: 2m20s to 7m23s to reconnect without the watch, measured
  after one laptop wake; with it, put-to-push took under 3 seconds.

## License

LGPL-3.0-or-later, same as stunmesh-go.
