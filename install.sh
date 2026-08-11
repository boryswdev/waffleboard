#!/usr/bin/env bash
# installs waffleboard into an isolated venv and links a launcher
# into ~/.local/bin so you can just run `waffleboard` from anywhere.
#
# this does NOT rely on Python packaging (no setup.py / pip -e),
# so it works no matter how the files were downloaded or arranged --
# it only needs waffleboard.py and requirements.txt to sit next to this script.
set -e

INSTALL_DIR="$HOME/.local/share/waffleboard"
BIN_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/waffleboard.py" ]; then
    echo "ERROR: waffleboard.py not found next to install.sh in $SCRIPT_DIR"
    echo "make sure waffleboard.py, requirements.txt and install.sh are all in the same folder."
    exit 1
fi

echo "==> Installing waffleboard to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"
cp "$SCRIPT_DIR/waffleboard.py" "$INSTALL_DIR/waffleboard.py"

echo "<==> creating virtual environment"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "<==> creating launcher at $BIN_DIR/waffleboard"
cat > "$BIN_DIR/waffleboard" <<'LAUNCHEREOF'
#!/usr/bin/env bash
exec "$HOME/.local/share/waffleboard/venv/bin/python" "$HOME/.local/share/waffleboard/waffleboard.py" "$@"
LAUNCHEREOF
chmod +x "$BIN_DIR/waffleboard"

echo ""
echo "== done. make sure $BIN_DIR is on your PATH, e.g.:"
echo '  export PATH="$HOME/.local/bin:$PATH"'
echo ""
echo "== Then just run:"
echo "  == 'waffleboard'"
