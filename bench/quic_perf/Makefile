# bench/quic_perf — TQUIC-style HTTP/3 benchmark harness
#
# Targets:
#   setup       : build images + generate certs/payloads (idempotent)
#   bench-mvp   : 12 cells × 3 iters = 36 runs (median absorbs cold-start noise)
#   bench-full  : 48-cell × 3-iter matrix (~75 min)
#   summary     : render Markdown table from results/*.json
#   clean       : remove generated payloads, results, SUMMARY.md

REPO_ROOT := $(shell git rev-parse --show-toplevel)
HERE      := $(REPO_ROOT)/bench/quic_perf

SERVERS   := navette tquic lsquic
PAYLOADS  := 1k 5k 15k 2m
SCENARIOS := long-conn short-conn
CLIENTS   := tquic_client h2load

.PHONY: setup bench-mvp bench-full summary clean help \
        build-runtime build-local build-tquic build-lsquic build-h2load gen-certs gen-payloads

help:
	@echo "Targets: setup build-local build-runtime bench-mvp bench-full summary clean"

setup: build-runtime build-local build-tquic build-lsquic build-h2load gen-certs gen-payloads
	@echo "[setup] all images built, local binaries compiled, certs and payloads ready"

build-runtime:
	@if ! docker image inspect navette-runtime:latest >/dev/null 2>&1; then \
	    echo "[setup] building navette-runtime:latest"; \
	    docker build -t navette-runtime:latest \
	        -f $(REPO_ROOT)/bench/Dockerfile.runtime $(REPO_ROOT); \
	else \
	    echo "[setup] navette-runtime:latest exists (skip)"; \
	fi

build-local:
	@$(HERE)/scripts/build-local.sh all

build-tquic:
	@if ! docker image inspect tquic-bench:latest >/dev/null 2>&1; then \
	    echo "[setup] building tquic-bench:latest"; \
	    docker build -t tquic-bench:latest \
	        -f $(HERE)/Dockerfile.tquic $(HERE); \
	else \
	    echo "[setup] tquic-bench:latest exists (skip)"; \
	fi

build-lsquic:
	@if ! docker image inspect lsquic-bench:latest >/dev/null 2>&1; then \
	    echo "[setup] building lsquic-bench:latest"; \
	    docker build -t lsquic-bench:latest \
	        -f $(HERE)/Dockerfile.lsquic $(HERE); \
	else \
	    echo "[setup] lsquic-bench:latest exists (skip)"; \
	fi

build-h2load:
	@if ! docker image inspect h2load-h3:latest >/dev/null 2>&1; then \
	    echo "[setup] building h2load-h3:latest"; \
	    docker build -t h2load-h3:latest \
	        -f $(REPO_ROOT)/bench/Dockerfile.h2load-h3 $(REPO_ROOT)/bench; \
	else \
	    echo "[setup] h2load-h3:latest exists (skip)"; \
	fi

gen-certs:
	@if [ ! -f $(REPO_ROOT)/certs/server.crt ]; then \
	    echo "[setup] generating ECDSA P-256 self-signed cert"; \
	    mkdir -p $(REPO_ROOT)/certs; \
	    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	        -keyout $(REPO_ROOT)/certs/server.key \
	        -out    $(REPO_ROOT)/certs/server.crt \
	        -days 365 -nodes -subj "/CN=localhost"; \
	else \
	    echo "[setup] $(REPO_ROOT)/certs/server.crt exists (skip)"; \
	fi

gen-payloads:
	@$(HERE)/scripts/gen-payloads.sh

bench-mvp:
	@echo "[bench-mvp] 12 cells × 3 iters = 36 runs"
	@for server in $(SERVERS); do \
	    for scenario in $(SCENARIOS); do \
	        for client in tquic_client h2load; do \
	            $(HERE)/scripts/bench.sh $$server 1k $$scenario $$client --iters 3; \
	        done; \
	    done; \
	done
	@$(HERE)/scripts/summarize.py

bench-full:
	@echo "[bench-full] 48 cells × 3 iters = 144 runs"
	@for server in $(SERVERS); do \
	    for payload in $(PAYLOADS); do \
	        for scenario in $(SCENARIOS); do \
	            for client in $(CLIENTS); do \
	                $(HERE)/scripts/bench.sh $$server $$payload $$scenario $$client --iters 3; \
	            done; \
	        done; \
	    done; \
	done
	@$(HERE)/scripts/summarize.py

summary:
	@$(HERE)/scripts/summarize.py

clean:
	@rm -f $(HERE)/payloads/*.bin
	@rm -f $(HERE)/results/*.json
	@rm -f $(HERE)/results/SUMMARY.md
	@echo "[clean] removed payloads/, results/*.json, SUMMARY.md (REFERENCE.md preserved)"
