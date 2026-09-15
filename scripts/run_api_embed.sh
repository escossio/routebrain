#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

. .venv-embed/bin/activate

if [ -f .env ]; then
  set -a
  . .env
  set +a
fi

export ROUTEBRAIN_EMBEDDING_PROVIDER="${ROUTEBRAIN_EMBEDDING_PROVIDER:-bge_m3_flagembedding}"
export ROUTEBRAIN_EMBEDDING_MODEL="${ROUTEBRAIN_EMBEDDING_MODEL:-BAAI/bge-m3}"
export ROUTEBRAIN_EMBEDDING_DIM="${ROUTEBRAIN_EMBEDDING_DIM:-1024}"
export ROUTEBRAIN_EMBEDDING_DEVICE="${ROUTEBRAIN_EMBEDDING_DEVICE:-cpu}"

exec .venv-embed/bin/python scripts/run_api_embed.py
