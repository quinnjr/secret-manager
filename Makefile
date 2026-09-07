PREFIX  ?= /usr
DESTDIR ?=
PAMDIR  ?= $(if $(wildcard /etc/debian_version),$(if $(shell /usr/bin/dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null),$(PREFIX)/lib/$(shell /usr/bin/dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)/security,$(PREFIX)/lib/security),$(PREFIX)/lib/security)
CARGO   ?= cargo
BIN     ?= target/release/secret-manager
# Built in its own CARGO_TARGET_DIR (see `build`) so the default build's
# tokio/zbus/clap-laden cdylib can never land here and be shipped as the PAM
# module.
PAMSO   ?= target/pam/release/libsecret_manager.so
COMPLETIONS_DIR ?= target/release/completions
BINDIR   = $(DESTDIR)$(PREFIX)/bin

SHELL = /bin/sh
.SHELLFLAGS = -ec

.PHONY: build install uninstall test

# Two builds of one crate: the default feature set gives the binary (no
# libpam, no PAM entry points), and the `pam` feature alone gives the cdylib
# PAM loads (no tokio, no zbus, no clap). The pam build gets its own
# CARGO_TARGET_DIR so its libsecret_manager.so can never be shadowed by (or
# shadow) the default build's same-named cdylib.
build:
	$(CARGO) build --release
	CARGO_TARGET_DIR=target/pam $(CARGO) build --release --no-default-features --features pam
	install -d $(COMPLETIONS_DIR)
	$(BIN) completions bash > $(COMPLETIONS_DIR)/sm
	$(BIN) completions zsh  > $(COMPLETIONS_DIR)/_sm
	$(BIN) completions fish > $(COMPLETIONS_DIR)/sm.fish

test:
	$(CARGO) test
	# The PAM feature is a library-only build: the integration tests pull the
	# crate back in with its default features, which the mutual-exclusion
	# guard in src/lib.rs correctly rejects.
	$(CARGO) build --no-default-features --features pam --lib

install:
	test -x $(BIN) && test -f $(PAMSO) && test -f $(COMPLETIONS_DIR)/sm && test -f $(COMPLETIONS_DIR)/_sm && test -f $(COMPLETIONS_DIR)/sm.fish || { echo "run 'make build' first (as your normal user)" >&2; exit 1; }
	# Fail closed unless $(PAMSO) really is the PAM build: the default build
	# emits a same-named libsecret_manager.so with no pam_sm_* symbols, and
	# shipping that into $(PAMDIR) would be a silently broken PAM module.
	if command -v nm >/dev/null 2>&1; then \
		nm -D --defined-only $(PAMSO) 2>/dev/null | grep -q pam_sm_open_session || { echo "$(PAMSO) is not the PAM build; run 'make build'" >&2; exit 1; }; \
	fi
	install -Dm755 $(BIN) $(BINDIR)/secret-manager
	if [ ! -e $(BINDIR)/sm ] || { [ -L $(BINDIR)/sm ] && [ "$$(readlink $(BINDIR)/sm)" = secret-manager ]; }; then \
		ln -sf secret-manager $(BINDIR)/sm; \
	else \
		echo "refusing to overwrite $(BINDIR)/sm: not a symlink to secret-manager" >&2; exit 1; \
	fi
	if [ ! -e $(BINDIR)/sm-askpass ] || { [ -L $(BINDIR)/sm-askpass ] && [ "$$(readlink $(BINDIR)/sm-askpass)" = secret-manager ]; }; then \
		ln -sf secret-manager $(BINDIR)/sm-askpass; \
	else \
		echo "refusing to overwrite $(BINDIR)/sm-askpass: not a symlink to secret-manager" >&2; exit 1; \
	fi
	install -Dm644 $(PAMSO) $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	for pair in dist/secret-manager.service:$(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service \
	            dist/org.freedesktop.secrets.service:$(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service \
	            dist/environment.d/50-secret-manager.conf:$(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf; do \
		src=$${pair%%:*}; dst=$${pair#*:}; tmp=$$(mktemp -p "$(DESTDIR)$(PREFIX)"); sed 's|/usr/bin/|$(PREFIX)/bin/|g' "$$src" > "$$tmp" && install -Dm644 "$$tmp" "$$dst"; rc=$$?; rm -f "$$tmp"; [ $$rc -eq 0 ]; \
	done
	install -Dm644 dist/pam.d/secret-manager $(DESTDIR)$(PREFIX)/share/doc/secret-manager/pam.d-snippet
	install -Dm644 docs/install-arch.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-arch.md
	install -Dm644 docs/install-debian.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-debian.md
	install -Dm644 docs/install-common.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-common.md
	install -Dm644 $(COMPLETIONS_DIR)/sm $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm
	install -Dm644 $(COMPLETIONS_DIR)/_sm $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm
	install -Dm644 $(COMPLETIONS_DIR)/sm.fish $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish

uninstall:
	@echo "If the service is running, stop it as your user: systemctl --user disable --now secret-manager.service" >&2
	rm -f $(BINDIR)/secret-manager
	for name in sm sm-askpass; do \
		if [ -L $(BINDIR)/$$name ] && [ "$$(readlink $(BINDIR)/$$name)" = secret-manager ]; then \
			rm -f $(BINDIR)/$$name; \
		fi; \
	done
	rm -f $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service
	rm -f $(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/secret-manager
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish
