ZIG ?= zig
GO ?= go

.PHONY: all server cli web run-server run-cli clean

all: server cli

server:
	$(ZIG) build server

cli:
	$(ZIG) build cli

# web:
# 	@[ -f web/go.mod ] && cd web && $(GO) build -o ../bin/pac-web . || echo "skip web"

run-server:
	$(ZIG) build run-server -- $(ARGS)

run-cli:
	$(ZIG) build run-cli -- $(ARGS)

# run-web:
# 	cd web && $(GO) run . $(ARGS)

clean:
	rm -rf zig-out .zig-cache bin
