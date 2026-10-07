# IRCHub Makefile
# Comprehensive build system for the IRCHub project

# ============================================================================
# Configuration
# ============================================================================

# Compiler: prefer gcc, fall back to clang, then cc, if gcc is not installed.
# An explicit `make CC=<compiler>` (command line / env) always wins.
ifeq ($(origin CC),default)
  CC := $(shell command -v gcc >/dev/null 2>&1 && echo gcc || \
                { command -v clang >/dev/null 2>&1 && echo clang; } || echo cc)
endif
$(info [build] using CC=$(CC))

# Project name
PROJECT = irchub

# Version
VERSION = 2.4.4

# Directories
SRC_DIR = .
BUILD_DIR = build
BIN_DIR = bin
OBJ_DIR = $(BUILD_DIR)/obj

# Source files
# One line: tools (the testnet) read this variable with a single-line match.
HUB_SOURCES = hub_main.c hub_config.c hub_crypto.c hub_logic.c hub_storage.c hub_update.c hub_reply.c hub_console.c hub_console_ui.c hub_console_fmt.c hub_console_core.c

# Object files
HUB_OBJECTS = $(HUB_SOURCES:%.c=$(OBJ_DIR)/%.o)

# Executables
HUB_TARGET = $(BIN_DIR)/irchub
KEYGEN_TARGET = $(BIN_DIR)/keygen

# ============================================================================
# Compiler Flags
# ============================================================================

# Detect OS so feature-test macros and library paths stay correct per-platform.
UNAME_S := $(shell uname -s)

# Base flags
CFLAGS = -Wall -Wextra -Wpedantic -std=c11

ifeq ($(UNAME_S),Linux)
# glibc + -std=c11 defines __STRICT_ANSI__ and hides POSIX symbols unless we
# explicitly request a POSIX environment.  _XOPEN_SOURCE adds the XSI part
# (realpath): glibc declares it without, musl does not (as in ircbot).
CFLAGS += -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
endif
# FreeBSD/other BSD: leaving _POSIX_C_SOURCE unset keeps __BSD_VISIBLE on, which
# is required for MSG_DONTWAIT and flock/LOCK_* used by the hub.

# The hub's self-update transport.  Drop this (and -lcurl below) to build a hub
# without the upgrade feature: every entry point in hub_update.c then reports it
# unavailable instead of falling back to anything.
CFLAGS += -DHAVE_CURL

# OpenSSL includes (adjust if needed)
INCLUDES = -I/usr/include -I/usr/local/include

# Libraries
# -lcurl is the hub's self-update transport (hub_update.c), guarded by
# HAVE_CURL exactly as ircbot guards its own updater: a hub built without it
# still builds and runs, and reports the upgrade feature unavailable.
LIBS = -lssl -lcrypto -lpthread -lcurl

# libssh: the hub's built-in SSH admin console (hub_console.c).  Always built
# in — it is the only way an admin reaches the hub.  The signed upstream
# tarball is pinned in third_party/ (sha256 checked before every build) and
# built as a minimal static library under $(BUILD_DIR)/libssh: server only, no
# SFTP, GSSAPI, zlib, pcap, examples, exec or group-exchange.  Needs cmake.
# Source: https://www.libssh.org/files/0.12/ (LGPL-2.1, see README).
LIBSSH_VERSION = 0.12.2
LIBSSH_SHA256  = 49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f
LIBSSH_TARBALL = third_party/libssh-$(LIBSSH_VERSION).tar.xz
LIBSSH_BUILD   = $(BUILD_DIR)/libssh
LIBSSH_PREFIX  = $(LIBSSH_BUILD)/inst
LIBSSH_LIB     = $(LIBSSH_PREFIX)/lib/libssh.a
LIBSSH_CMAKE   = -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
                 -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_LIBDIR=lib \
                 -DWITH_SERVER=ON -DWITH_SFTP=OFF -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF \
                 -DWITH_PCAP=OFF -DWITH_EXAMPLES=OFF -DWITH_NACL=OFF -DWITH_GEX=OFF \
                 -DWITH_EXEC=OFF -DWITH_DEBUG_CALLTRACE=OFF -DWITH_SYMBOL_VERSIONING=OFF \
                 -DWITH_PKCS11_URI=OFF -DWITH_FIDO2=OFF -DUNIT_TESTING=OFF
INCLUDES += -I$(LIBSSH_PREFIX)/include
HUB_LIBS = $(LIBSSH_LIB) $(LIBS)

# Linker flags
LDFLAGS =

# Ports install third-party libs under /usr/local on the BSDs.
ifneq ($(UNAME_S),Linux)
LDFLAGS += -L/usr/local/lib
endif

# ============================================================================
# Build Modes
# ============================================================================

# Default: Release build
ifndef BUILD_MODE
	BUILD_MODE = release
endif

# Debug mode flags
ifeq ($(BUILD_MODE),debug)
	CFLAGS += -g3 -O0 -DDEBUG -fno-omit-frame-pointer
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

# Release mode flags
ifeq ($(BUILD_MODE),release)
	CFLAGS += -O2 -g -DNDEBUG -D_FORTIFY_SOURCE=2
	CFLAGS += -fstack-protector-strong -fPIE
	LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now
endif

# Production mode flags — release hardening + maximum optimization
ifeq ($(BUILD_MODE),production)
	CFLAGS += -O3 -DNDEBUG -march=native -flto=auto
	CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
	LDFLAGS += -flto=auto -s -pie -Wl,-z,relro -Wl,-z,now
endif

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean distclean install uninstall help test valgrind \
        directories debug release production check-openssl keygen libssh

# Default target
all: directories check-openssl $(HUB_TARGET) $(KEYGEN_TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BUILD_DIR)

# Check OpenSSL version
check-openssl:
	@echo "Checking OpenSSL version..."
	@if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then \
		echo "OpenSSL version: $$(pkg-config --modversion openssl)"; \
	else \
		echo "Note: pkg-config/openssl.pc not found; relying on compiler default include paths (e.g. FreeBSD base OpenSSL or /usr/local)"; \
	fi
	@echo ""

# ============================================================================
# Hub Server
# ============================================================================

$(HUB_TARGET): $(HUB_OBJECTS) $(LIBSSH_LIB)
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $(HUB_OBJECTS) $(HUB_LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

# The pinned static libssh (see LIBSSH_* above).  Built once per build tree
# with the same compiler; `make clean` removes it with the rest of build/.
$(LIBSSH_LIB): $(LIBSSH_TARBALL)
	@echo "Building libssh $(LIBSSH_VERSION) (static, server only)..."
	@command -v cmake >/dev/null 2>&1 || { echo "error: cmake is required to build libssh"; exit 1; }
	@sum=$$( (sha256sum $(LIBSSH_TARBALL) 2>/dev/null || shasum -a 256 $(LIBSSH_TARBALL)) | cut -d' ' -f1); \
		[ "$$sum" = "$(LIBSSH_SHA256)" ] || \
		{ echo "error: $(LIBSSH_TARBALL) does not match the pinned sha256"; exit 1; }
	@rm -rf $(LIBSSH_BUILD) && mkdir -p $(LIBSSH_BUILD)/obj
	@tar -xoJf $(LIBSSH_TARBALL) -C $(LIBSSH_BUILD)
	@cd $(LIBSSH_BUILD)/obj && CC="$(CC)" cmake ../libssh-$(LIBSSH_VERSION) \
		$(LIBSSH_CMAKE) -DCMAKE_INSTALL_PREFIX=$(abspath $(LIBSSH_PREFIX)) \
		> ../cmake.log 2>&1 || { cat ../cmake.log; exit 1; }
	@$(MAKE) -C $(LIBSSH_BUILD)/obj -j4 install > $(LIBSSH_BUILD)/make.log 2>&1 || \
		{ tail -40 $(LIBSSH_BUILD)/make.log; exit 1; }
	@echo "Built: $@"

# Just the library (the testnet builds it into its own BUILD_DIR).
libssh: $(LIBSSH_LIB)

# ============================================================================
# Key Generator Utility
# ============================================================================

# keygen.c + bcrypt_pbkdf.c are self-contained (OpenSSL only) and
# byte-identical to their ircbot/utils copies — they link nothing from the hub.
$(KEYGEN_TARGET): $(OBJ_DIR)/keygen.o $(OBJ_DIR)/bcrypt_pbkdf.o
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

$(OBJ_DIR)/keygen.o: keygen.c bcrypt_pbkdf.h
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/bcrypt_pbkdf.o: bcrypt_pbkdf.c bcrypt_pbkdf.h
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ============================================================================
# Object Files
# ============================================================================

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c hub.h
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# hub_console.c includes libssh's headers, which exist once the library is built.
$(HUB_OBJECTS): | $(LIBSSH_LIB)

$(OBJ_DIR)/hub_console.o $(OBJ_DIR)/hub_console_ui.o $(OBJ_DIR)/hub_console_fmt.o: hub_console.h hub_console_ui.h hub_console_fmt.h
$(OBJ_DIR)/hub_console_core.o: hub_console.h hub_reply.h
$(OBJ_DIR)/hub_logic.o $(OBJ_DIR)/hub_reply.o: hub_reply.h hub_console.h

# ============================================================================
# Build Modes (shortcuts)
# ============================================================================

debug:
	@$(MAKE) BUILD_MODE=debug all

release:
	@$(MAKE) BUILD_MODE=release all

production:
	@$(MAKE) BUILD_MODE=production all

# ============================================================================
# Utility Tools
# ============================================================================

# keygen.c is hand-maintained (Curve25519); do not auto-generate
keygen: $(KEYGEN_TARGET)

# ============================================================================
# Installation
# ============================================================================

# Installation paths
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc/irchub
DATADIR = $(PREFIX)/share/irchub
LOGDIR = /var/log/irchub

install: all
	@echo "Installing IRCHub..."
	@install -d $(BINDIR)
	@install -d $(SYSCONFDIR)
	@install -d $(DATADIR)
	@install -d $(LOGDIR)
	@install -m 0755 $(HUB_TARGET) $(BINDIR)/irchub
	@install -m 0755 $(KEYGEN_TARGET) $(BINDIR)/hub_keygen
	@echo "Installed to $(PREFIX)"
	@echo ""
	@echo "First-time setup:"
	@echo "  1. On the first admin's machine: $(BINDIR)/hub_keygen <name>"
	@echo "  2. Run setup (imports that .public.b64): $(BINDIR)/irchub -setup"
	@echo "  3. Start (prompts for the config password): $(BINDIR)/irchub"
	@echo ""
	@echo "Utilities:"
	@echo "  - Admin console: hub_keygen <name> also writes <ts>_<name>_ed25519, then"
	@echo "    ssh -i <ts>_<name>_ed25519 -o IdentitiesOnly=yes -p <hubport> <name>@<hub>"
	@echo ""

uninstall:
	@echo "Uninstalling IRCHub..."
	@rm -f $(BINDIR)/irchub
	@rm -f $(BINDIR)/hub_keygen
	@# hub_decrypt/hub_encrypt: no longer built; removed if an older install left them.
	@rm -f $(BINDIR)/hub_decrypt
	@rm -f $(BINDIR)/hub_encrypt
	@echo "Uninstalled from $(PREFIX)"
	@echo "Note: Config files in $(SYSCONFDIR) and logs in $(LOGDIR) were not removed"

# ============================================================================
# Testing & Debugging
# ============================================================================

# Run basic tests
test: debug
	@echo "Running basic tests..."
	@echo "Note: Implement your test suite here"
	@# Add your test commands here

# Memory leak detection with Valgrind
valgrind: debug
	@echo "Running Valgrind memory check..."
	@echo "Note: set HUB_PASS before running the hub binary"
	@valgrind --leak-check=full \
	          --show-leak-kinds=all \
	          --track-origins=yes \
	          --verbose \
	          --log-file=valgrind-hub.log \
	          $(HUB_TARGET) &
	@echo "Valgrind output will be in valgrind-hub.log"

# Static analysis with cppcheck (if available)
analyze:
	@command -v cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --suppress=missingIncludeSystem \
		         --inconclusive --std=c11 $(SRC_DIR)/*.c || \
		echo "cppcheck not found, skipping static analysis"

# ============================================================================
# Cleaning
# ============================================================================

clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(BIN_DIR)
	@rm -f *.log
	@echo "Clean complete"

distclean: clean
	@echo "Removing all generated files..."
	@rm -f .irchub.cnf
	@rm -f hub_private.pem hub_public.pem
	@rm -f irchub.log
	@rm -f *.o *.a *.so
	@rm -f core core.*
	@echo "Distclean complete"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "IRCHub Build System v$(VERSION)"
	@echo ""
	@echo "Usage: make [target] [BUILD_MODE=mode]"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  debug        - Build with debug symbols and sanitizers"
	@echo "  release      - Build optimized release version"
	@echo "  production   - Build maximum optimization for production"
	@echo "  keygen       - Build the keypair generator (bin/keygen)"
	@echo "  install      - Install to $(PREFIX)"
	@echo "  uninstall    - Remove installed files"
	@echo "  test         - Run test suite"
	@echo "  valgrind     - Run Valgrind memory check"
	@echo "  analyze      - Run static code analysis"
	@echo "  clean        - Remove build files"
	@echo "  distclean    - Remove all generated files"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Build Modes:"
	@echo "  debug        - Debug build with sanitizers (default)"
	@echo "  release      - Optimized release build"
	@echo "  production   - Maximum optimization"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build release version"
	@echo "  make debug              # Build debug version"
	@echo "  make BUILD_MODE=debug   # Same as above"
	@echo "  make clean all          # Clean rebuild"
	@echo "  make install PREFIX=/opt/irchub  # Install to /opt"
	@echo ""
	@echo "After building:"
	@echo "  bin/keygen robert             # IRC + SSH keypairs for admin 'robert' (on their machine)"
	@echo "  bin/irchub -setup             # Initial setup (imports robert's .public.b64)"
	@echo "  bin/irchub                    # Run hub (prompts for the config password)"
	@echo "  ssh -i <ts>_robert_ed25519 -p 7000 robert@127.0.0.1  # Admin console"
	@echo "  bin/keygen --passwd <ts>_robert.private.b64  # Add/change the passphrase"
	@echo ""

# ============================================================================
# Dependencies
# ============================================================================

# Auto-generate dependencies (not for clean: generating them needs libssh's
# headers, i.e. a libssh build)
ifeq ($(filter clean distclean help libssh,$(MAKECMDGOALS)),)
-include $(HUB_OBJECTS:.o=.d)
endif

# Pattern rule for dependency generation
$(OBJ_DIR)/%.d: $(SRC_DIR)/%.c | $(LIBSSH_LIB)
	@mkdir -p $(OBJ_DIR)
	@$(CC) -MM $(CFLAGS) $(INCLUDES) $< | \
		sed 's,\($*\)\.o[ :]*,$(OBJ_DIR)/\1.o $@ : ,g' > $@

# ============================================================================
# Package Creation (Optional)
# ============================================================================

PACKAGE_NAME = $(PROJECT)-$(VERSION)
PACKAGE_DIR = $(BUILD_DIR)/$(PACKAGE_NAME)

package: production
	@echo "Creating package $(PACKAGE_NAME)..."
	@mkdir -p $(PACKAGE_DIR)/bin
	@mkdir -p $(PACKAGE_DIR)/doc
	@cp $(BIN_DIR)/* $(PACKAGE_DIR
	@cp README.md $(PACKAGE_DIR)/doc/ 2>/dev/null || true
	@echo "Installation: make install" > $(PACKAGE_DIR)/INSTALL
	@cd $(BUILD_DIR) && tar czf $(PACKAGE_NAME).tar.gz $(PACKAGE_NAME)
	@echo "Package created: $(BUILD_DIR)/$(PACKAGE_NAME).tar.gz"

# ============================================================================
# Special Targets
# ============================================================================

.PRECIOUS: $(OBJ_DIR)/%.o
.SUFFIXES:
.DELETE_ON_ERROR:
