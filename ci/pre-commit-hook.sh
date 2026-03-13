#!/usr/bin/env bash
# dejavu Git Pre-commit Hook
# 安装: cp dejavu/ci/pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -euo pipefail

DEJAVU_DIR="$(git rev-parse --show-toplevel)/dejavu"
OPENCLAW_DIR="$(git rev-parse --show-toplevel)"
SCORE_THRESHOLD=70

if [ ! -f "${DEJAVU_DIR}/dejavu.sh" ]; then
    echo "[dejavu] dejavu.sh not found — skipping security check"
    exit 0
fi

echo "[dejavu] Running pre-commit security baseline check..."

# Bug Fix #49: set -euo pipefail (line 6) causes the hook to exit immediately when
# dejavu.sh returns exit code 1/2/3, making EXIT_CODE=$? unreachable.
# This would block ALL commits on MEDIUM findings (exit 1) — not the intended behavior.
# Fix: capture exit code explicitly without relying on set -e to not kill the script.
EXIT_CODE=0
"${DEJAVU_DIR}/dejavu.sh" \
    -d "${OPENCLAW_DIR}" \
    -c config,network,auth \
    -o terminal \
    2>&1 || EXIT_CODE=$?

if [ "${EXIT_CODE}" -ge 3 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║  dejavu: CRITICAL issues found — commit BLOCKED  ║"
    echo "║  Run: ./dejavu/dejavu.sh -d . --fix             ║"
    echo "╚══════════════════════════════════════════════╝"
    exit 1
fi

if [ "${EXIT_CODE}" -ge 2 ]; then
    echo ""
    echo "[dejavu] WARNING: HIGH severity findings detected."
    echo "        Review dejavu/output/ before merging to main."
fi

exit 0
