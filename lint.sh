#!/bin/sh

set -e

uv run ruff check src/payloads/dump_heap.py analyze_heap.py
uv run ruff format src/payloads/dump_heap.py analyze_heap.py
uv run mypy --strict src/payloads/dump_heap.py analyze_heap.py
cargo clippy
cargo fmt
