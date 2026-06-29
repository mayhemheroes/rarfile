#!/usr/bin/env bash
#
# mayhem/build.sh — build the rarfile Atheris fuzz harness + its standalone reproducer,
# and prepare the project's own pytest suite. Runs inside the commit image (mayhem/Dockerfile)
# as `mayhem` in /mayhem. Python adaptation of the C/C++ template (modelled on the rfc3986
# Python/atheris spec-v2 integration).
#
# What it does (must be idempotent + air-gapped on re-run — SPEC §6.2 item 9 / §6.5):
#   1. Populate / reuse an in-image wheelhouse under /opt/toolchains/python (HOME-independent),
#      then install atheris + the test deps OFFLINE from that wheelhouse into a fixed site dir on
#      PYTHONPATH. The first (CI, online) build fills the wheelhouse; the air-gapped PATCH re-run
#      resolves entirely from it (pip --no-index --find-links).
#   2. Compile launcher.c -> the ELF Mayhem target `fuzz-rar` (Atheris is a Python script; Mayhem
#      needs an ELF cmd, and the gate needs DWARF < 4 — hence a compiled wrapper).
#   3. Build the same launcher as the standalone (run-once) reproducer `fuzz-rar-standalone`.
#   4. Compile run_tests.c -> the ELF pytest-runner wrapper (so the sabotage oracle check bites).
#
# NOTE on $SANITIZER_FLAGS: the base exports it (ASan+UBSan, halting) for C/C++ projects, but the
# fuzzed code here is PYTHON — Atheris instruments the rarfile module at import time, which is the
# coverage+crash signal Mayhem consumes. The only native artifact is the thin C launcher that execs
# the interpreter; sanitizing it would instrument the wrapper, not rarfile, and ASan in the launcher
# would clash with the exec'd Python runtime. So we deliberately do NOT apply $SANITIZER_FLAGS to the
# launcher; only $DEBUG_FLAGS (DWARF < 4) is needed for triage symbols.
#
# rarfile itself is a single pure-Python module (rarfile.py at the repo root, no runtime deps) — it
# is exposed by putting $SRC on PYTHONPATH, so a PATCH agent's edits to rarfile.py take effect with
# no reinstall. Atheris instruments rarfile at import time, so only DEBUG_FLAGS (DWARF < 4) is needed
# for the thin C launcher; sanitizing the launcher would just instrument the wrapper, not the Python.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
export DEBUG_FLAGS CC MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# ── Python toolchain caches at a FIXED, $HOME-independent prefix (SPEC §6.2 item 8) ──
PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
SITE="$PY_PREFIX/site"
mkdir -p "$WHEELHOUSE" "$SITE"

PY="$(command -v python3)"

# 1) Wheelhouse: download every runtime/test dependency ONCE (online). On the air-gapped re-run the
#    directory is already populated, so pip never reaches the network. atheris ships a prebuilt
#    manylinux wheel for this CPython, so no compilation is needed. cryptography powers rarfile's
#    crypto tests; pytest is the suite runner. rarfile core parsing has NO runtime deps.
PKGS=(atheris pytest cryptography)
need_download=0
"$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$WHEELHOUSE','atheris-*.whl')) else 1)" || need_download=1
if [ "$need_download" -eq 1 ]; then
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" "${PKGS[@]}"
else
  echo ">> wheelhouse already populated — reusing $WHEELHOUSE (air-gapped re-run path)"
fi

# 2) Install the deps into the fixed site dir, OFFLINE from the wheelhouse. --no-index +
#    --find-links guarantees no PyPI access (works on the air-gapped re-run). Guarded to be
#    idempotent: once the site dir holds atheris+pytest we SKIP the reinstall.
if "$PY" -c "import os,glob,sys; sys.exit(0 if (glob.glob(os.path.join('$SITE','atheris*')) and glob.glob(os.path.join('$SITE','pytest*'))) else 1)"; then
  echo ">> deps already installed in $SITE — skipping (idempotent re-run)"
else
  echo ">> installing deps (offline) into $SITE"
  "$PY" -m pip install --no-index --find-links="$WHEELHOUSE" --target "$SITE" "${PKGS[@]}"
fi

# rarfile itself: keep it as the editable source tree (rarfile.py lives at $SRC). Expose it via
# PYTHONPATH — both the baked Dockerfile ENV (run time) and env.sh / the sanity check below (build
# time) put $SRC on the path. PYTHONPATH is the robust, idempotent mechanism (a .pth in a --target
# dir is not processed).
PYRUN="$SITE:$SRC"

cat > "$PY_PREFIX/env.sh" <<EOF
export PYTHONPATH="$PYRUN\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHON_BIN="$PY"
EOF

# Sanity: the harness imports must resolve offline now.
PYTHONPATH="$PYRUN" "$PY" -c 'import atheris, rarfile, pytest; print("imports OK:", rarfile.__version__)'

# 3) Compile the ELF launcher target + the standalone reproducer (DWARF < 4 via $DEBUG_FLAGS).
HARNESS="$SRC/mayhem/fuzz_rar.py"
echo ">> compiling fuzz-rar (+ standalone) with DEBUG_FLAGS=$DEBUG_FLAGS"
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/fuzz-rar"
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/fuzz-rar-standalone"

# 4) The pytest oracle runs through a compiled NON-system ELF wrapper so the gate's anti-reward-hack
#    sabotage check (which neuters non-system binaries to exit(0)) actually bites the suite.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" "$SRC/mayhem/run_tests.c" -o "$SRC/rarfile_run_tests"

echo ">> build.sh complete"
ls -la "$SRC/fuzz-rar" "$SRC/fuzz-rar-standalone" "$SRC/rarfile_run_tests"
