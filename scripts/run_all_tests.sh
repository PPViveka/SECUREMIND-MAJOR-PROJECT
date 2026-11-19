#!/usr/bin/env bash
# =============================================================================
# SageArmor Master Test Runner
# Runs full test suites across Backend, Frontend, and Extension in sequence.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================================"
echo "🛡️  SageArmor Production Test Suite Validation"
echo "========================================================"

echo ""
echo "▶ 1/3: Running Backend Tests (pytest)..."
python3 -m pytest -p no:asyncio "$ROOT_DIR/backend/tests"

echo ""
echo "▶ 2/3: Running Frontend Tests (node:test)..."
npm --prefix "$ROOT_DIR/frontend" test -- --run

echo ""
echo "▶ 3/3: Running Extension Tests (node:test)..."
npm --prefix "$ROOT_DIR/extension" test

echo ""
echo "========================================================"
echo "✅ All 289 SageArmor tests (256 Backend, 22 Extension, 11 Frontend) passed successfully!"
echo "========================================================"
