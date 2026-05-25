#!/bin/sh
# Continuous git snapshot loop body. Per design-docs/origin/06--2026-05-24-0623-arb-auditability.md §4.
#
# Run from cron (launchd / systemd / crontab - the substrate is a
# deployment detail, not a design choice). Cadence: every minute.
#
# What it does:
#   1. cd to the arbiter root.
#   2. git add -A stages every change in the tree (respecting
#      arbiter/.gitignore, which already excludes state/, bitcoin/,
#      lnd/, data/, *.pyc, etc.).
#   3. git diff --cached --quiet returns non-zero when there is real
#      staged change. The || clause therefore commits only when there
#      is something to commit; quiescent minutes produce no commit.
#   4. The commit message is a UTC ISO-8601 timestamp so git log
#      reads chronologically even without committer-date rewriting.
#
# That is the entire job. The design rests on there being nothing
# clever here - a non-AI reviewer reads this in five seconds.
#
# Configuration:
#   ARBITER_ROOT  Path to the arbiter tree (the directory containing
#                 src/, config/, bin/, .gitignore). Defaults to the
#                 parent of this script's directory, so the canonical
#                 deployment ($ARBITER/ops/snapshot.sh) needs no env
#                 setup.
#
# Bootstrap (one-shot, run by the operator before enabling the cron):
#   cd $ARBITER && git init && git add -A && git commit -m 'initial'
# After that, every cron firing extends the history.

set -e

here="$(cd "$(dirname "$0")" && pwd)"
ARBITER_ROOT="${ARBITER_ROOT:-$(cd "$here/.." && pwd)}"

cd "$ARBITER_ROOT"
git add -A
git diff --cached --quiet || git commit -q -m "snapshot: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
