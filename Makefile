# IRCHub Makefile
# Comprehensive build system for the IRCHub project

# ============================================================================
# Configuration
# ============================================================================

# Compiler
CC = gcc

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

# Object files
HUB_OBJECTS = $(HUB_SOURCES:%.c=$(OBJ_DIR)/%.o)
ADMIN_OBJECTS = $(ADMIN_SOURCES:%.c=$(OBJ_DIR)/%.o)
DECRYPT_OBJECTS = $(DECRYPT_SOURCES:%.c=$(OBJ_DIR)/%.o)

# Executables
HUB_TARGET = $(BIN_DIR)/irchub
ADMIN_TARGET = $(BIN_DIR)/hub_admin
KEYGEN_TARGET = $(BIN_DIR)/keygen
DECRYPT_TARGET = $(BIN_DIR)/hub_decrypt

# ============================================================================
# Compiler Flags
# ============================================================================

# Base flags
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L

# OpenSSL includes (adjust if needed)
INCLUDES = -I/usr/include -I/usr/local/include

# Libraries
LIBS = -lssl -lcrypto -lpthread

# Linker flags
LDFLAGS = -L/usr/lib -L/usr/local/lib

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
	CFLAGS += -O2 -DNDEBUG -D_FORTIFY_SOURCE=2
	CFLAGS += -fstack-protector-strong -fPIE
	LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now
endif

# Production mode flags (maximum optimization)
ifeq ($(BUILD_MODE),production)
	CFLAGS += -O3 -DNDEBUG -march=native -flto
	LDFLAGS += -flto -s
endif

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean distclean install uninstall help test valgrind \
        directories debug release production check-openssl keygen

# Default target
all: directories check-openssl $(HUB_TARGET) $(ADMIN_TARGET) $(KEYGEN_TARGET) $(DECRYPT_TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BUILD_DIR)

# Check OpenSSL version
check-openssl:
	@echo "Checking OpenSSL version..."
	@pkg-config --exists openssl && \
		echo "OpenSSL version: $$(pkg-config --modversion openssl)" || \
		echo "Warning: pkg-config cannot find OpenSSL, build may fail"
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

# Create keygen.c if it doesn't exist
keygen: keygen.c $(KEYGEN_TARGET)

keygen.c:
	@echo "Creating keygen.c utility..."
	@echo '#include "hub.h"' > keygen.c
	@echo '#include <stdio.h>' >> keygen.c
	@echo '#include <stdlib.h>' >> keygen.c
	@echo '' >> keygen.c
	@echo 'int main(int argc, char *argv[]) {' >> keygen.c
	@echo '    char *priv_pem = NULL, *pub_pem = NULL;' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    printf("Generating RSA-2048 keypair...\\n");' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    if (!hub_crypto_generate_keypair(&priv_pem, &pub_pem)) {' >> keygen.c
	@echo '        fprintf(stderr, "Key generation failed\\n");' >> keygen.c
	@echo '        return 1;' >> keygen.c
	@echo '    }' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    const char *priv_file = (argc > 1) ? argv[1] : "hub_private.pem";' >> keygen.c
	@echo '    const char *pub_file = (argc > 2) ? argv[2] : "hub_public.pem";' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    FILE *fp = fopen(priv_file, "w");' >> keygen.c
	@echo '    if (!fp) {' >> keygen.c
	@echo '        perror("Failed to create private key file");' >> keygen.c
	@echo '        free(priv_pem); free(pub_pem);' >> keygen.c
	@echo '        return 1;' >> keygen.c
	@echo '    }' >> keygen.c
	@echo '    fputs(priv_pem, fp);' >> keygen.c
	@echo '    fclose(fp);' >> keygen.c
	@echo '    printf("Private key written to: %s\\n", priv_file);' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    fp = fopen(pub_file, "w");' >> keygen.c
	@echo '    if (!fp) {' >> keygen.c
	@echo '        perror("Failed to create public key file");' >> keygen.c
	@echo '        free(priv_pem); free(pub_pem);' >> keygen.c
	@echo '        return 1;' >> keygen.c
	@echo '    }' >> keygen.c
	@echo '    fputs(pub_pem, fp);' >> keygen.c
	@echo '    fclose(fp);' >> keygen.c
	@echo '    printf("Public key written to: %s\\n", pub_file);' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    secure_wipe(priv_pem, strlen(priv_pem));' >> keygen.c
	@echo '    free(priv_pem);' >> keygen.c
	@echo '    free(pub_pem);' >> keygen.c
	@echo '    ' >> keygen.c
	@echo '    printf("\\nDone! You can now run setup:\\n");' >> keygen.c
	@echo '    printf("  ./bin/irchub <password> -setup\\n");' >> keygen.c
	@echo '    return 0;' >> keygen.c
	@echo '}' >> keygen.c
	@echo "Created keygen.c"

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
	@echo "Installed to $(PREFIX)"
	@echo ""
	@echo "First-time setup:"
	@echo "  1. Generate keys: $(BINDIR)/hub_keygen"
	@echo "  2. Run setup: $(BINDIR)/irchub <password> -setup"
	@echo "  3. Start hub: $(BINDIR)/irchub <password>"
	@echo ""
	@echo "Utilities:"
	@echo "  - Admin client: $(BINDIR)/hub_admin <ip> <port> <pub.pem>"
	@echo "  - Decrypt config: $(BINDIR)/hub_decrypt [config_file]"
	@echo ""

uninstall:
	@echo "Uninstalling IRCHub..."
	@rm -f $(BINDIR)/irchub
	@rm -f $(BINDIR)/hub_admin
	@rm -f $(BINDIR)/hub_keygen
	@rm -f $(BINDIR)/hub_decrypt
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
	@valgrind --leak-check=full \
	          --show-leak-kinds=all \
	          --track-origins=yes \
	          --verbose \
	          --log-file=valgrind-hub.log \
	          $(HUB_TARGET) test_password &
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
	@rm -f keygen.c
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
	@echo "  ./bin/hub_keygen                    # Generate keys"
	@echo "  ./bin/irchub mypass -setup          # Initial setup"
	@echo "  ./bin/irchub mypass                 # Run hub"
	@echo "  ./bin/hub_admin 127.0.0.1 6667 hub_public.pem  # Admin client"
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
	@cp $(BIN_DIR)/* $(PACKAGE_DIR)/bin/
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
