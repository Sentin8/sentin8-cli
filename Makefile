# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:CLI
# SPDX-License-Identifier: Apache-2.0

# Makefile — sentin8-cli (starter repo, RS §4.5)
#
# Self-contained dev controls for THIS starter. Sources the root .env for
# fleet env, guarantees the dev infra, and uses an ABSOLUTE
# SENTIN8_CAPTAIN_BINARY_PREFIX (cwd-independent — RS §4.5.1-1).
SHELL := /bin/bash
CARGO ?= cargo
RELEASE ?=

.PHONY: help build test status clean

help: ## Show this help
	@echo "sentin8-cli (starter repo)"
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## cargo build (dev profile; RELEASE=--release for release)
	@$(CARGO) build $(RELEASE)

status: ## Fleet status via this CLI (the group Makefile is the fleet surface)
	@$(CARGO) run $(RELEASE) --quiet --bin sentin8-cli -- captain services

test: ## cargo test
	@$(CARGO) test

clean: ## cargo clean
	@$(CARGO) clean
