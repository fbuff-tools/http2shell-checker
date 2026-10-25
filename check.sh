#!/bin/sh
# HTTP2Shell / Node2Shell (CVE-2026-111497) version check.
# Reads the versions installed on this machine or container and compares them with the fixed releases.
# It only reads versions: nothing is sent anywhere and nothing is changed.
#
# Usage: sh check.sh
# Run it in every runtime that matters: each container image, CI runner and server.

# Fixed releases (published from October 21, 2026). Keep in sync with https://fbuff.com/tools/http2shell-checker/
NODE_FIXED_22=22.23.4
NODE_FIXED_24=24.22.1
NODE_FIXED_26=26.12.1
BUN_FIXED=1.4.4
PYTHON_BROTLI_FIXED=1.2.1
BROTLICFFI_FIXED=1.2.1.0
DEBIAN_FIXED_BOOKWORM=1.0.9-2+deb12u1
DEBIAN_FIXED_TRIXIE=1.1.0-2+deb13u1

found=0
exposed=0

# version_ge A B: true when dotted version A >= B
version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

report() { # name version verdict detail
  printf '%-16s %-22s %s%s\n' "$1" "$2" "$3" "${4:+  ($4)}"
  found=1
  case "$3" in VULNERABLE|END-OF-LIFE) exposed=1 ;; esac
}

if command -v node >/dev/null 2>&1; then
  v=$(node --version | sed 's/^v//')
  major=${v%%.*}
  case "$major" in
    22) fixed=$NODE_FIXED_22 ;;
    24) fixed=$NODE_FIXED_24 ;;
    26) fixed=$NODE_FIXED_26 ;;
    *) fixed= ;;
  esac
  if [ -n "$fixed" ]; then
    if version_ge "$v" "$fixed"; then report "Node.js" "$v" "patched"; else report "Node.js" "$v" "VULNERABLE" "update to $fixed"; fi
  elif [ "$major" -gt 26 ]; then
    report "Node.js" "$v" "patched"
  else
    report "Node.js" "$v" "END-OF-LIFE" "no fix for Node.js $major: move to 22, 24 or 26"
  fi
fi

if command -v bun >/dev/null 2>&1; then
  v=$(bun --version)
  if version_ge "$v" "$BUN_FIXED"; then report "Bun" "$v" "patched"; else report "Bun" "$v" "VULNERABLE" "update to $BUN_FIXED, rebuild bun build --compile binaries"; fi
fi

for py in python3 python; do
  command -v "$py" >/dev/null 2>&1 || continue
  for pkg in Brotli brotlicffi; do
    v=$("$py" -m pip show "$pkg" 2>/dev/null | sed -n 's/^Version: *//p')
    [ -n "$v" ] || continue
    if [ "$pkg" = Brotli ]; then fixed=$PYTHON_BROTLI_FIXED; else fixed=$BROTLICFFI_FIXED; fi
    if ! version_ge "$v" 1.0.3; then report "pip $pkg" "$v" "not affected" "older than Brotli 1.0.3"
    elif version_ge "$v" "$fixed"; then report "pip $pkg" "$v" "patched"
    else report "pip $pkg" "$v" "VULNERABLE" "pip install -U $pkg>=$fixed"; fi
  done
  break
done

if command -v dpkg-query >/dev/null 2>&1; then
  v=$(dpkg-query -W -f '${Version}' libbrotli1 2>/dev/null)
  if [ -n "$v" ]; then
    case "$v" in
      1.0.9-*) fixed=$DEBIAN_FIXED_BOOKWORM ;;
      1.1.0-*) fixed=$DEBIAN_FIXED_TRIXIE ;;
      *) fixed= ;;
    esac
    if [ -z "$fixed" ]; then
      report "libbrotli1" "$v" "check vendor" "no fixed build known for this version yet"
    elif dpkg --compare-versions "$v" ge "$fixed"; then
      report "libbrotli1" "$v" "patched"
    else
      report "libbrotli1" "$v" "VULNERABLE" "sudo apt update && sudo apt install --only-upgrade libbrotli1"
    fi
  fi
fi

if [ "$found" = 0 ]; then
  echo "No Node.js, Bun, Python Brotli or Debian libbrotli1 found here."
  echo "Other software can bundle Brotli: paste its version into https://fbuff.com/tools/http2shell-checker/"
fi
[ "$exposed" = 1 ] && echo "Update, then restart services and rebuild images. Details: https://fbuff.com/tools/http2shell-checker/"
exit "$exposed"
