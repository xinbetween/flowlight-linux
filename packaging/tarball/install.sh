#!/bin/sh
#
# Installs what is in this directory, for a distribution nobody has packaged.
#
# Two files and a message. It does not enable anything, it does not start anything, and it does not write
# outside the two directories named below — a tarball that reaches further than its own paths is a tarball
# nobody can undo.
set -eu

prefix=/usr
units=/usr/lib/systemd/system
uninstall=no

usage() {
    cat <<'SAID'
usage: ./install.sh [--prefix /usr] [--units /usr/lib/systemd/system] [--uninstall]

  --prefix     where the binary goes; `/usr` puts it in /usr/sbin
  --units      where the systemd unit goes, if this machine has systemd
  --uninstall  take both away again, leaving the database alone
SAID
}

while [ $# -gt 0 ]; do
    case $1 in
        --prefix) prefix=${2:?--prefix needs a path}; shift 2 ;;
        --units) units=${2:?--units needs a path}; shift 2 ;;
        --uninstall) uninstall=yes; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ "$(id -u)" != 0 ]; then
    echo "This writes to $prefix/sbin, so it needs root: sudo ./install.sh" >&2
    exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)

if [ "$uninstall" = yes ]; then
    rm -f "$prefix/sbin/flowlightd" "$units/flowlightd.service"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop flowlightd >/dev/null 2>&1 || true
        systemctl disable flowlightd >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    # The database stays. Somebody taking the binary off is not usually asking for the record of what their
    # machine has been doing to be deleted, and `rm -rf /var/lib/flowlight` is one command and theirs to type.
    echo "Removed flowlightd and its unit. /var/lib/flowlight was left alone."
    exit 0
fi

test -f "$here/flowlightd" || { echo "no flowlightd beside this script" >&2; exit 1; }

install -d -m 755 "$prefix/sbin"
install -m 755 "$here/flowlightd" "$prefix/sbin/flowlightd"

# Only where systemd keeps its units. A machine without systemd — Alpine, Void — gets the binary and is told
# so, rather than getting a unit file nothing will ever read.
unit_installed=no
if [ -d "$(dirname "$units")" ]; then
    install -d -m 755 "$units"
    install -m 644 "$here/flowlightd.service" "$units/flowlightd.service"
    unit_installed=yes
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi

cat <<SAID

Flowlight is installed and is not running.

That is on purpose: it reads every HTTPS request on this machine, and starting
that because somebody ran an installer would be the wrong way round.

  sudo $prefix/sbin/flowlightd                watch, in this terminal
SAID

# Offered only where it would work. A suggestion that cannot run on the machine reading it is worse than no
# suggestion: it sends somebody looking for what they did wrong.
if [ "$unit_installed" = yes ]; then
    echo "  sudo systemctl enable --now flowlightd      watch from now on"
else
    echo "  (no $units here, so no systemd unit was installed)"
fi

cat <<SAID
  $prefix/sbin/flowlightd budget              what it is allowed to read, and for how long

  ./install.sh --uninstall                    take it off again

SAID
