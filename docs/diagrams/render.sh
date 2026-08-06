#!/usr/bin/env bash
# Re-render every README diagram. PlantUML sources are the EDITABLE original — the .svg/.png
# beside them are build output, regenerated from these, never hand-edited.
#
#   brew install plantuml graphviz     # or: apt install plantuml graphviz
#   ./docs/diagrams/render.sh
set -euo pipefail
cd "$(dirname "$0")"
command -v plantuml >/dev/null || { echo "plantuml not found (brew install plantuml)"; exit 1; }
for f in [0-9]*.puml; do
  plantuml -tsvg "$f"
  plantuml -tpng "$f"
  echo "rendered ${f%.puml}"
done
