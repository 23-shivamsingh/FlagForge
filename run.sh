#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY_CHECK'
import sys
if sys.version_info < (3, 10):
    raise SystemExit('FlagForge requires Python 3.10+; install a newer Python with Homebrew.')
PY_CHECK
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python3 -m pip install -r requirements.txt
printf '\nFlagForge starting locally: http://127.0.0.1:8787\n'
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8787
