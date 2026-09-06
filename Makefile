PREFIX  ?= /usr
DESTDIR ?=
PAMDIR  ?= $(PREFIX)/lib/security
CARGO   ?= cargo
BIN      = target/release/secret-manager
PAMSO    = target/release/libpam_secret_manager.so
BINDIR   = $(DESTDIR)$(PREFIX)/bin

.PHONY: build install uninstall test

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

install: build
	install -Dm755 $(BIN) $(BINDIR)/secret-manager
	ln -sf secret-manager $(BINDIR)/sm
	ln -sf secret-manager $(BINDIR)/sm-askpass
	install -Dm755 $(PAMSO) $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	install -Dm644 dist/secret-manager.service $(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service
	install -Dm644 dist/org.freedesktop.secrets.service $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service
	install -Dm644 dist/environment.d/50-secret-manager.conf $(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf
	install -Dm644 dist/pam.d/secret-manager $(DESTDIR)$(PREFIX)/share/doc/secret-manager/pam.d-snippet
	install -Dm644 docs/install-arch.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-arch.md
	install -Dm644 docs/install-debian.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-debian.md
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions $(DESTDIR)$(PREFIX)/share/zsh/site-functions $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	$(BIN) completions bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm
	$(BIN) completions zsh  > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm
	$(BIN) completions fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish

uninstall:
	rm -f $(BINDIR)/secret-manager $(BINDIR)/sm $(BINDIR)/sm-askpass
	rm -f $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service
	rm -f $(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/secret-manager
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish
