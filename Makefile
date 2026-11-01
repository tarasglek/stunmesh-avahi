# Release artifact per arch, stunmesh-bundle-linux-<arch>-<version>.tar.gz:
#   stunmesh/bin/stunmesh-go   stunmesh-go with opendht, lease and avahi linked in
#   stunmesh/licenses/         stunmesh-go and stunmesh-avahi licenses
#   stunmesh/*                 deploy/: config generator, installers, units
# No site config goes in: mesh.yaml and rendered node configs stay with the user.
# stunmesh-go itself is pinned in go.mod.
VERSION ?= $(shell git describe --tags --always --dirty)
ARCHES ?= amd64 arm64
GO_VERSION ?= 1.26.9
GOARCH ?= $(shell go env GOARCH)

BUILD := build
DIST := dist
GO_SRC := go.mod go.sum $(shell find . -name '*.go' -not -path './build/*' -not -path './dist/*')
DEPLOY_SRC := $(shell find deploy -type f)
BUNDLES := $(foreach a,$(ARCHES),$(DIST)/stunmesh-bundle-linux-$(a)-$(VERSION).tar.gz)

# Reproducible: same commit, same bytes. Pin the toolchain, reset environment
# that changes codegen, and stamp tar entries with the commit time.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct)
export CGO_ENABLED := 0
export GOTOOLCHAIN := go$(GO_VERSION)
export GOFLAGS :=
export GOEXPERIMENT :=
export GOAMD64 := v1
export GOARM64 := v8.0

.PHONY: build check dist release test clean
build: $(BUILD)/stunmesh-go-$(GOARCH)

.PRECIOUS: $(BUILD)/stunmesh-go-%
$(BUILD)/stunmesh-go-%: $(GO_SRC)
	GOOS=linux GOARCH=$* go build -trimpath -ldflags '-s -w' -o $@ ./cmd/stunmesh-go

# Plugins are created inside app.New, before anything touches WireGuard, so
# this runs as a normal user: reaching "running in oneshot mode" means every
# plugin in check.yaml was found and built.
check: build test
	-$(BUILD)/stunmesh-go-$(GOARCH) -c check.yaml -oneshot > $(BUILD)/check.log 2>&1
	grep -q 'running in oneshot mode' $(BUILD)/check.log

dist: $(DIST)/SHA256SUMS

$(DIST)/SHA256SUMS: $(BUNDLES)
	cd $(DIST) && sha256sum $(notdir $^) > SHA256SUMS

$(DIST)/stunmesh-bundle-linux-%-$(VERSION).tar.gz: $(BUILD)/stunmesh-go-% $(DEPLOY_SRC)
	rm -rf $(BUILD)/stage-$*
	mkdir -p $(BUILD)/stage-$*/stunmesh/bin $(BUILD)/stage-$*/stunmesh/licenses $(DIST)
	cp -R deploy/. $(BUILD)/stage-$*/stunmesh/
	cp $< $(BUILD)/stage-$*/stunmesh/bin/stunmesh-go
	upstream=$$(go list -m -f '{{.Dir}}' github.com/tjjh89017/stunmesh-go) && for f in LICENSE LICENSE.GPL; do \
		cp $$upstream/$$f $(BUILD)/stage-$*/stunmesh/licenses/stunmesh-go-$$f; \
		cp $$f $(BUILD)/stage-$*/stunmesh/licenses/stunmesh-avahi-$$f; \
	done
	chmod -R u+w $(BUILD)/stage-$*/stunmesh/licenses
	tar -C $(BUILD)/stage-$* --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
		--mode=u+rwX,go+rX,go-w --mtime=@$(SOURCE_DATE_EPOCH) -cf - stunmesh | gzip -9n > $@

release: dist
	git describe --tags --exact-match HEAD >/dev/null
	test -z "$$(git status --porcelain)"
	gh release create $(VERSION) --generate-notes $(BUNDLES) $(DIST)/SHA256SUMS

test:
	go test ./...

clean:
	rm -rf $(BUILD) $(DIST)
