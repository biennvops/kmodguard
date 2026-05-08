PREFIX ?= /usr
SYSCONFDIR ?= /etc
LIBEXECDIR ?= $(PREFIX)/libexec
SYSTEMD_UNIT_DIR ?= $(SYSCONFDIR)/systemd/system
RUNTIME_DIR ?= /run/kmodguard
BIN_DIR ?= $(PREFIX)/bin

BUILD_PROFILE ?= release
TARGET_DIR ?= target/$(BUILD_PROFILE)

.PHONY: build check-build install install-binaries install-systemd install-config-sample install-runtime uninstall

build:
	cargo build --workspace --$(BUILD_PROFILE)

check-build:
	@test -x "$(TARGET_DIR)/kmodctl" || (echo "Missing $(TARGET_DIR)/kmodctl; run 'make build' first." && exit 1)
	@test -x "$(TARGET_DIR)/kmodguard" || (echo "Missing $(TARGET_DIR)/kmodguard; run 'make build' first." && exit 1)

install: check-build install-binaries install-systemd install-runtime

install-binaries:
	install -d "$(DESTDIR)$(BIN_DIR)"
	install -m 0755 "$(TARGET_DIR)/kmodctl" "$(DESTDIR)$(BIN_DIR)/kmodctl"
	install -d "$(DESTDIR)$(LIBEXECDIR)/kmodguard"
	install -m 0755 "$(TARGET_DIR)/kmodguard" "$(DESTDIR)$(LIBEXECDIR)/kmodguard/kmodguard"

install-systemd:
	install -d "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	install -m 0644 "packaging/systemd/kmodguard.service" "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/kmodguard.service"
	install -d "$(DESTDIR)$(LIBEXECDIR)/kmodguard"
	install -m 0755 "packaging/systemd/kmodguard-hook" "$(DESTDIR)$(LIBEXECDIR)/kmodguard/kmodguard-hook"

install-runtime:
	install -d "$(DESTDIR)$(RUNTIME_DIR)"

uninstall:
	rm -f "$(DESTDIR)$(BIN_DIR)/kmodctl"
	rm -f "$(DESTDIR)$(LIBEXECDIR)/kmodguard/kmodguard"
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/kmodguard.service"
	rm -f "$(DESTDIR)$(LIBEXECDIR)/kmodguard/kmodguard-hook"
