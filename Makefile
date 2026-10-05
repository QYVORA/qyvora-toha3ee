# toha3ee — network exploitation & MITM framework.
#
# Common targets:
#   make build            build the binary for this platform
#   make install          install to PATH via scripts/install.sh (root: /usr/local/bin, else ~/.local/bin)
#   make install-data     install the menu entry and icon for an existing install
#   make uninstall        remove the installed binary
#   make test / vet / fmt  quality gates
#   make release          package this platform's binary into dist/

BIN    := toha3ee
GO     ?= go
PREFIX ?=

ICON    := assets/toha3ee.png
DESKTOP := assets/toha3ee.desktop

# The ecosystem installs icons at 512x512; this tree's own uninstall lines named
# 256x256, which matched nothing that was ever written.
APPDIR  := $(DESTDIR)$(PREFIX)/share/applications
ICONDIR := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps

.PHONY: all build install install-data uninstall test vet fmt clean release winres man

all: build

build:
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/toha3ee

install:
	@if [ -z "$(PREFIX)" ]; then sh scripts/install.sh --from-source; \
	 else sh scripts/install.sh --from-source --prefix "$(PREFIX)"; fi
	@$(MAKE) --no-print-directory install-data

# The menu entry and the icon are installed independently. A missing icon is
# decoration; the entry is how the tool is found, so one must not cost the other.
#
# The entry passes --no-sudo. This tool escalates to root for its privileged
# operations, but a menu launch has no one to answer a sudo prompt, so the
# unprivileged interface is the only one that can actually start from a menu.
install-data:
	@if [ -f "$(DESKTOP)" ]; then \
		install -d $(APPDIR); \
		sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/$(BIN).desktop; \
		chmod 0644 $(APPDIR)/$(BIN).desktop; \
		update-desktop-database $(APPDIR) 2>/dev/null || true; \
	else \
		echo "toha3ee: $(DESKTOP) missing; installed the command without a menu entry."; \
	fi
	@if [ -f "$(ICON)" ]; then \
		install -d $(ICONDIR); \
		install -m 0644 $(ICON) $(ICONDIR)/$(BIN).png; \
		gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true; \
	else \
		echo "toha3ee: $(ICON) missing; menu entry installed without an icon."; \
	fi

# Validate that every man page renders cleanly with the system troff.
man:
	@for page in man/*.[17]; do \
	  nroff -man "$$page" >/dev/null 2>&1 || { echo "man: $$page fails to render"; exit 1; }; \
	  echo "man: $$page ok"; \
	done

uninstall:
	@printf "rm -f \$$HOME/.local/bin/$(BIN) /usr/local/bin/$(BIN) \$$(CURDIR)/$(BIN)\n"
	@printf "rm -f \$$HOME/.local/share/icons/hicolor/512x512/apps/$(BIN).png /usr/local/share/icons/hicolor/512x512/apps/$(BIN).png\n"
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
