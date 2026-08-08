# toha3ee — network exploitation & MITM framework.
#
# Common targets:
#   make build            build the binary for this platform
#   make install          install to PATH via scripts/install.sh (root: /usr/local/bin, else ~/.local/bin)
#   make uninstall        remove the installed binary
#   make test / vet / fmt  quality gates
#   make release          package this platform's binary into dist/

BIN    := toha3ee
GO     ?= go
PREFIX ?=

.PHONY: all build install uninstall test vet fmt clean release winres man

all: build

build:
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/toha3ee

install:
	@if [ -z "$(PREFIX)" ]; then sh scripts/install.sh --from-source; \
	 else sh scripts/install.sh --from-source --prefix "$(PREFIX)"; fi

# Validate that every man page renders cleanly with the system troff.
man:
	@for page in man/*.[17]; do \
	  nroff -man "$$page" >/dev/null 2>&1 || { echo "man: $$page fails to render"; exit 1; }; \
	  echo "man: $$page ok"; \
	done

uninstall:
	@printf "rm -f \$$HOME/.local/bin/$(BIN) /usr/local/bin/$(BIN) \$$(CURDIR)/$(BIN)\n"
	@printf "rm -f \$$HOME/.local/share/icons/hicolor/256x256/apps/$(BIN).png /usr/local/share/icons/hicolor/256x256/apps/$(BIN).png\n"
	@printf "rm -f \$$HOME/.local/share/applications/$(BIN).desktop /usr/local/share/applications/$(BIN).desktop\n"

# Regenerate the Windows executable resources (icon + version info) into a
# .syso that `go build` links in for windows/amd64. Requires network.
winres:
	cd cmd/$(BIN) && $(GO) run github.com/tc-hib/go-winres@v0.3.3 make --in ../../winres/winres.json

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	@out="$$(gofmt -l cmd internal pkg)"; if [ -n "$$out" ]; then echo "needs formatting:"; echo "$$out"; exit 1; fi

clean:
	rm -f $(BIN)
	rm -rf dist

# Local convenience build: packages this platform's binary into dist/. The
# full multi-OS/multi-arch release matrix is produced by the GitHub Actions
# workflow (.github/workflows/release.yml) on a version tag.
release: clean build
	mkdir -p dist
	@os="$$(uname -s | tr '[:upper:]' '[:lower:]')"; arch="$$(uname -m)"; \
	case "$$arch" in x86_64) arch=amd64;; aarch64) arch=arm64;; esac; \
	if [ "$$os" = "linux" ]; then \
	  tar -czf "dist/$(BIN)_$${os}_$${arch}.tar.gz" $(BIN) assets/toha3ee.png; \
	else \
	  tar -czf "dist/$(BIN)_$${os}_$${arch}.tar.gz" $(BIN); \
	fi; \
	sha256sum "dist/$(BIN)_$${os}_$${arch}.tar.gz" | awk '{print $$1}' > "dist/$(BIN)_$${os}_$${arch}.sha256"; \
	echo "packaged dist/$(BIN)_$${os}_$${arch}.tar.gz"
