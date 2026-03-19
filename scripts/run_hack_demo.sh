#!/bin/zsh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f ".venv/bin/activate" ]]; then
  source ".venv/bin/activate"
fi

python -m examples.hack_the_agent_demo
