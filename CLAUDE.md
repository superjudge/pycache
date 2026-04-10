# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pycache is an experimental distributed hash table (DHT) implementation that acts as a drop-in replacement for memcached. It is loosely based on the Kademlia DHT algorithm and supports the memcached text protocol. It is explicitly a toy/learning project, not for production use.

## Running and Testing

**Setup (first time):**
```bash
uv sync
```

**Run tests:**
```bash
uv run python pycache_test.py
```

**Start a node:**
```bash
uv run python pycache.py --addr 127.0.0.1:6000
uv run python pycache.py --addr 127.0.0.1:6001 --peer 127.0.0.1:6000  # join existing mesh
```

**Debug mode** (enables verbose logging and the `dump` command):
```bash
uv run python pycache.py --addr 127.0.0.1:6000 --debug
```

Dependencies are declared in `pyproject.toml`. Python 3.12+ is required. No CI configuration exists.

## Architecture

Everything lives in two files: `pycache.py` (implementation) and `pycache_test.py` (unit tests).

### Key Classes in `pycache.py`

- **`LocalMemcachedClient`** — Wraps a plain dict to provide a memcached-like interface. Values are stored as `(flags, exptime, data)` tuples. Handles expiration and numeric operations.

- **`RemoteMemcachedClient`** — TCP client that speaks the memcached text protocol to remote nodes. Also handles the custom overlay protocol commands (`peers`, `join`, `leave`).

- **`CacheHandler`** — Handles a single TCP connection. Contains the command REPL: parses memcached commands, forwards requests to the responsible node (via `RemoteMemcachedClient`) or handles them locally, and implements rebalancing when nodes join.

- **`CacheServer`** — Represents a single DHT node. Holds the local cache, the node's ID (`kid` = SHA1 of its address), and the set of known peers. Uses `gevent.server.StreamServer` for non-blocking I/O.

- **`JoinGreenlet`** — Spawned when a node starts with `--peer`. Contacts the peer to discover all existing nodes, then broadcasts a `join` notification to each.

### DHT Design

- **Node/Key IDs:** 160-bit SHA1 hashes. Node ID = SHA1 of `"<ip>:<port>"`.
- **Distance metric:** XOR between hashes (Kademlia-style).
- **Routing:** Every node knows all other nodes (full mesh — no k-buckets). A lookup takes at most 2 hops: client → correct node, or client → any node → correct node.
- **Key responsibility:** The node whose ID has the smallest XOR distance to the key's hash owns that key.
- **Rebalancing:** When a new node joins, existing nodes check all their keys and transfer any that are now closer to the new node.

### Concurrency Model

Uses `gevent` greenlets — single-threaded cooperative concurrency. The code is **not thread-safe**, which is intentional. There is no connection pooling; each inter-node RPC opens a fresh TCP connection.

### Protocol Extensions

Beyond standard memcached commands, the overlay adds:
- `peers` — returns all known peer addresses
- `join <addr>` — notifies a node that a new peer has joined
- `leave <addr>` — notifies a node that a peer has left
- `dump` — debug dump (only in `--debug` mode)

### Known Limitations (by design)

- Text protocol only; no binary protocol, no `cas`/`gets`, no `stats`, no `flush_all`.
- Data cannot contain `\r\n` (the protocol framing delimiter).
- No replication — data is lost if a node fails.
- No connection pooling or caching.
