#!/usr/bin/env bash
######################################################################
# .what = set one file of an installed dependency via a pnpm patch
#
# .why  = a defect in a dependency we do not own is cured upstream;
#         until that release lands, a pnpm patch carries the cure here.
#         pnpm writes the patch, its hash, and the lockfile entry, so
#         `pnpm install --frozen-lockfile` in ci applies it as-is.
#
# usage:
#   set.package.patch.sh --package <name>@<version> --file <path-in-pkg> --from <path>              # plan
#   set.package.patch.sh --package <name>@<version> --file <path-in-pkg> --from <path> --mode apply # apply
#
# options:
#   --package   dependency + exact installed version (required)
#   --file      path of the file inside the package to replace (required)
#   --from      repo path of the full new content for that file (required)
#   --mode      plan (default) | apply
#
# guarantee:
#   - plan prints the diff of the file and writes naught
#   - apply re-runs from a fresh edit dir, so a re-run converges
#   - the patch lands in patches/, config + lockfile via pnpm itself
#   - exit 0 = done, 1 = malfunction, 2 = bad input
######################################################################
set -euo pipefail

PACKAGE=""
FILE=""
FROM=""
MODE="plan"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package) PACKAGE="$2"; shift 2 ;;
    --file) FILE="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --skill|--repo|--role) shift 2 ;;
    --help|-h) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "✋ ConstraintError: unknown argument: $1" >&2; echo "   └─ fix: see --help" >&2; exit 2 ;;
  esac
done

# reject absent inputs
if [[ -z "$PACKAGE" || -z "$FILE" || -z "$FROM" ]]; then
  echo "✋ ConstraintError: --package, --file, and --from are required" >&2
  echo "   └─ fix: set.package.patch.sh --package <name>@<version> --file <path-in-pkg> --from <path>" >&2
  exit 2
fi
if [[ "$MODE" != "plan" && "$MODE" != "apply" ]]; then
  echo "✋ ConstraintError: --mode must be plan or apply, got '$MODE'" >&2
  exit 2
fi
if [[ ! -f "$FROM" ]]; then
  echo "✋ ConstraintError: --from '$FROM' is not a file" >&2
  exit 2
fi

# locate the installed file
NAME="${PACKAGE%@*}"
INSTALLED="node_modules/$NAME/$FILE"
if [[ ! -f "$INSTALLED" ]]; then
  echo "✋ ConstraintError: '$INSTALLED' is not installed" >&2
  echo "   └─ fix: check --package name and --file path; run npm ci if node_modules is absent" >&2
  exit 2
fi

echo "🐢 lets patch $PACKAGE"
echo ""
echo "🐚 set.package.patch"
echo "   ├─ package: $PACKAGE"
echo "   ├─ file: $FILE"
echo "   ├─ from: $FROM"
echo "   └─ mode: $MODE"
echo ""
echo "🔭 diff"
diff -u "$INSTALLED" "$FROM" || true
echo ""

# plan stops here
if [[ "$MODE" == "plan" ]]; then
  echo "🌊 plan only; add --mode apply to write the patch"
  exit 0
fi

# write the patch from a fresh edit dir
EDIT_DIR=".temp/set.package.patch/${NAME//\//+}"
rm -rf "$EDIT_DIR"
mkdir -p "$(dirname "$EDIT_DIR")"
pnpm patch "$PACKAGE" --edit-dir "$EDIT_DIR"
cp "$FROM" "$EDIT_DIR/$FILE"
pnpm patch-commit "$EDIT_DIR"
rm -rf "$EDIT_DIR"

echo ""
echo "✨ patch set"
echo "   └─ installed now: $INSTALLED"
diff -q "$INSTALLED" "$FROM" && echo "      └─ matches --from ✓"
