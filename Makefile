# Release artifacts per arch:
#   stunmesh-avahi-linux-<arch>                  standalone plugin
#   stunmesh-bundle-linux-<arch>-<version>.tar.gz, everything to run the mesh:
#     stunmesh/bin/stunmesh-bb                   stunmesh-go + stunmesh-avahi, one makebb binary
#     stunmesh/bin/stunmesh-go -> stunmesh-bb
#     stunmesh/bin/stunmesh-avahi -> stunmesh-bb
#     stunmesh/bin/stunmesh-opendht-shell        store plugin (shell script)
#     stunmesh/licenses/                         stunmesh-go and stunmesh-avahi licenses
#     stunmesh/*                                 deploy/: config generator, installers, units
# No site config goes in: mesh.yaml and rendered node configs stay with the user.
VERSION ?= $(shell git describe --tags --always --dirty)
STUNMESH_VERSION ?= v1.15.1
# Tags can move; the build refuses any other commit.
STUNMESH_COMMIT ?= bc0922007e81e1a9abdff38988d2cb8c44a4d208
MAKEBB_VERSION ?= v0.3.0
ARCHES ?= amd64 arm64
# makebb selects files by the go.work version but compiles with the toolchain;
# they must match or version-tagged files go missing.
GO_VERSION ?= 1.26.9

BUILD := build
DIST := dist
STUNMESH_SRC := $(BUILD)/stunmesh-go-$(STUNMESH_VERSION)
MAKEBB := $(abspath $(BUILD)/bin/makebb)
GO_SRC := go.mod go.sum $(wildcard *.go)
DEPLOY_SRC := $(shell find deploy -type f)

DIST_FILES := $(foreach a,$(ARCHES),$(DIST)/stunmesh-avahi-linux-$(a) $(DIST)/stunmesh-bundle-linux-$(a)-$(VERSION).tar.gz)

# Reproducible: same commit, same bytes. Pin the toolchain, reset environment
# that changes codegen, and stamp tar entries with the commit time.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct)
export CGO_ENABLED := 0
export GOTOOLCHAIN := go$(GO_VERSION)
export GOFLAGS :=
export GOEXPERIMENT :=
export GOAMD64 := v1
export GOARM64 := v8.0

.PHONY: dist release test clean
dist: $(DIST)/SHA256SUMS

$(DIST)/SHA256SUMS: $(DIST_FILES)
	cd $(DIST) && sha256sum $(notdir $^) > SHA256SUMS

$(DIST)/stunmesh-avahi-linux-%: $(GO_SRC)
	GOOS=linux GOARCH=$* go build -trimpath -ldflags '-s -w' -o $@ .

$(STUNMESH_SRC)/go.mod:
	rm -rf $(STUNMESH_SRC)
	git clone -q --depth 1 --branch $(STUNMESH_VERSION) https://github.com/tjjh89017/stunmesh-go $(STUNMESH_SRC)
	test "$$(git -C $(STUNMESH_SRC) rev-parse HEAD)" = $(STUNMESH_COMMIT)

# Built for the host: makebb itself must not inherit the target GOARCH.
$(MAKEBB):
	GOBIN=$(dir $@) go install github.com/u-root/gobusybox/src/cmd/makebb@$(MAKEBB_VERSION)

# makebb only resolves multiple modules through a workspace.
$(BUILD)/go.work: Makefile
	mkdir -p $(BUILD)
	printf 'go %s\n\nuse (\n\t./%s\n\t..\n)\n' $(GO_VERSION) $(notdir $(STUNMESH_SRC)) > $@

$(DIST)/stunmesh-bundle-linux-%-$(VERSION).tar.gz: $(GO_SRC) $(DEPLOY_SRC) $(STUNMESH_SRC)/go.mod $(BUILD)/go.work $(MAKEBB)
	rm -rf $(BUILD)/stage-$*
	mkdir -p $(BUILD)/stage-$*/stunmesh/bin $(BUILD)/stage-$*/stunmesh/licenses $(DIST)
	cp -R deploy/. $(BUILD)/stage-$*/stunmesh/
	cd $(BUILD) && GOOS=linux GOARCH=$* $(MAKEBB) -go-build-tags builtin_all -go-enable-inlining \
		-o stage-$*/stunmesh/bin/stunmesh-bb ./$(notdir $(STUNMESH_SRC)) ..
	ln -s stunmesh-bb $(BUILD)/stage-$*/stunmesh/bin/stunmesh-go
	ln -s stunmesh-bb $(BUILD)/stage-$*/stunmesh/bin/stunmesh-avahi
	install -m 755 $(STUNMESH_SRC)/contrib/opendht-shell/opendht-shell.sh $(BUILD)/stage-$*/stunmesh/bin/stunmesh-opendht-shell
	for f in LICENSE LICENSE.GPL; do \
		cp $(STUNMESH_SRC)/$$f $(BUILD)/stage-$*/stunmesh/licenses/stunmesh-go-$$f; \
		cp $$f $(BUILD)/stage-$*/stunmesh/licenses/stunmesh-avahi-$$f; \
	done
	tar -C $(BUILD)/stage-$* --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
		--mode=u+rwX,go+rX,go-w --mtime=@$(SOURCE_DATE_EPOCH) -cf - stunmesh | gzip -9n > $@

release: dist
	git describe --tags --exact-match HEAD >/dev/null
	test -z "$$(git status --porcelain)"
	gh release create $(VERSION) --generate-notes $(DIST_FILES) $(DIST)/SHA256SUMS

test:
	go test ./...

clean:
	rm -rf $(BUILD) $(DIST)
