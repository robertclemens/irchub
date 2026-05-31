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
VERSION = 2.0

# Directories
SRC_DIR = .
BUILD_DIR = build
BIN_DIR = bin
OBJ_DIR = $(BUILD_DIR)/obj

# Source files
HUB_SOURCES = hub_main.c hub_config.c hub_crypto.c hub_logic.c hub_storage.c
ADMIN_SOURCES = hub_admin.c hub_crypto.c
DECRYPT_SOURCES = hub_decrypt.c hub_crypto.c
ENCRYPT_SOURCES = hub_encrypt.c hub_crypto.c

# Object files
HUB_OBJECTS = $(HUB_SOURCES:%.c=$(OBJ_DIR)/%.o)
ADMIN_OBJECTS = $(ADMIN_SOURCES:%.c=$(OBJ_DIR)/%.o)
DECRYPT_OBJECTS = $(DECRYPT_SOURCES:%.c=$(OBJ_DIR)/%.o)
ENCRYPT_OBJECTS = $(ENCRYPT_SOURCES:%.c=$(OBJ_DIR)/%.o)

# Executables
HUB_TARGET = $(BIN_DIR)/irchub
ADMIN_TARGET = $(BIN_DIR)/hub_admin
KEYGEN_TARGET = $(BIN_DIR)/keygen
DECRYPT_TARGET = $(BIN_DIR)/hub_decrypt
ENCRYPT_TARGET = $(BIN_DIR)/hub_encrypt

# ============================================================================
# Compiler Flags
# ============================================================================

# Detect OS so feature-test macros and library paths stay correct per-platform.
UNAME_S := $(shell uname -s)

# Base flags
CFLAGS = -Wall -Wextra -Wpedantic -std=c11

ifeq ($(UNAME_S),Linux)
# glibc + -std=c11 defines __STRICT_ANSI__ and hides POSIX symbols unless we
# explicitly request a POSIX environment.
CFLAGS += -D_POSIX_C_SOURCE=200809L
endif
# FreeBSD/other BSD: leaving _POSIX_C_SOURCE unset keeps __BSD_VISIBLE on, which
# is required for MSG_DONTWAIT and flock/LOCK_* used by the hub.

# OpenSSL includes (adjust if needed)
INCLUDES = -I/usr/include -I/usr/local/include

# Libraries
LIBS = -lssl -lcrypto -lpthread

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
        directories debug release production check-openssl keygen

# Default target
all: directories check-openssl $(HUB_TARGET) $(ADMIN_TARGET) $(KEYGEN_TARGET) $(DECRYPT_TARGET) $(ENCRYPT_TARGET)

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

$(HUB_TARGET): $(HUB_OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

# ============================================================================
# Admin Client
# ============================================================================

$(ADMIN_TARGET): $(ADMIN_OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

# ============================================================================
# Key Generator Utility
# ============================================================================

$(KEYGEN_TARGET): $(OBJ_DIR)/keygen.o $(OBJ_DIR)/hub_crypto.o
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

$(OBJ_DIR)/keygen.o: keygen.c hub.h
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ============================================================================
# Config Decryption Utility
# ============================================================================

$(DECRYPT_TARGET): $(DECRYPT_OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

# ============================================================================
# Config Encryption Utility
# ============================================================================

$(ENCRYPT_TARGET): $(ENCRYPT_OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Built: $@ (mode: $(BUILD_MODE))"
	@echo ""

# ============================================================================
# Object Files
# ============================================================================

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c hub.h
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

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
	@install -m 0755 $(ADMIN_TARGET) $(BINDIR)/hub_admin
	@install -m 0755 $(KEYGEN_TARGET) $(BINDIR)/hub_keygen
	@install -m 0755 $(DECRYPT_TARGET) $(BINDIR)/hub_decrypt
	@install -m 0755 $(ENCRYPT_TARGET) $(BINDIR)/hub_encrypt
	@echo "Installed to $(PREFIX)"
	@echo ""
	@echo "First-time setup:"
	@echo "  1. Generate keys: $(BINDIR)/hub_keygen"
	@echo "  2. Run setup: $(BINDIR)/irchub -setup"
	@echo "  3. Set env and start: export HUB_PASS=<password> && $(BINDIR)/irchub"
	@echo ""
	@echo "Utilities:"
	@echo "  - Admin client: $(BINDIR)/hub_admin <ip> <port> <pub.pem>"
	@echo "  - Decrypt config: $(BINDIR)/hub_decrypt [config_file]"
	@echo "  - Encrypt config: $(BINDIR)/hub_encrypt [input_file] [output_file]"
	@echo ""

uninstall:
	@echo "Uninstalling IRCHub..."
	@rm -f $(BINDIR)/irchub
	@rm -f $(BINDIR)/hub_admin
	@rm -f $(BINDIR)/hub_keygen
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
	@echo "  keygen       - Create and build key generator utility"
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
	@echo "  hub_keygen                    # Generate keys"
	@echo "  irchub -setup                          # Initial setup"
	@echo "  export HUB_PASS=mypass && irchub       # Run hub"
	@echo "  hub_admin 127.0.0.1 6667 hub_public.pem  # Admin client"
	@echo ""

# ============================================================================
# Dependencies
# ============================================================================

# Auto-generate dependencies
-include $(HUB_OBJECTS:.o=.d)
-include $(ADMIN_OBJECTS:.o=.d)

# Pattern rule for dependency generation
$(OBJ_DIR)/%.d: $(SRC_DIR)/%.c
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
