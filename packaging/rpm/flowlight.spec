# The daemon, as an RPM. Built from a binary that already exists rather than from source in `%build`:
# the binary is statically linked, so the machine that compiles it has nothing to do with the machine that
# runs it, and compiling it again inside a Fedora container would only prove that Fedora has a Rust compiler.
#
# Only the daemon. The window is linked against the system's GTK *and* the system's glibc, so a window built
# on Ubuntu 24.04 does not run on openSUSE Leap 15.6, whose glibc is older. Shipping one anyway would be
# shipping a package that installs and does not start, which is the exact bug v0.5.0 exists to have fixed.
# Building it inside each distribution is its own piece of work and is on the roadmap as one.
#
# `Release: 1` with no `%{?dist}`, deliberately. This package is not Fedora's or openSUSE's — it is the same
# file for both, and a `.fc41` in the name would claim otherwise.

Name:           flowlight
Version:        %{version}
Release:        1
Summary:        Watch what every process says on the network, before encryption
License:        GPL-3.0-only
URL:            https://github.com/xinbetween/flowlight-linux
BuildArch:      %{architecture}

# There are none. A statically linked binary needs the kernel, and the kernel is not a package — so the
# automatic scan is turned off rather than left to add something that happens to be in the build root.
AutoReqProv:    no

%description
Flowlight reads HTTPS as an application hands it to its TLS library, so no
certificate is installed anywhere and certificate pinning is not involved. It
attributes every connection to the process that opened it and to the agent that
caused it, refuses connections in the kernel, and states plainly what it could
not see.

The daemon needs root, because loading an eBPF program does. Its systemd unit
ships disabled: a tool that reads every HTTPS request on a machine should not
start doing it because somebody installed it.

Statically linked, so it has no libc requirement and runs on any distribution
with a kernel of 4.18 or later. The eBPF programs are compiled into the binary,
so there are no kernel headers to match and nothing to rebuild when the kernel
is upgraded.

%install
rm -rf %{buildroot}
install -D -m 755 %{built}/flowlightd %{buildroot}%{_sbindir}/flowlightd
install -D -m 644 %{unit} %{buildroot}%{_unitdir}/flowlightd.service
install -D -m 644 %{licence} %{buildroot}%{_licensedir}/%{name}/COPYING

%files
%{_sbindir}/flowlightd
%config(noreplace) %{_unitdir}/flowlightd.service
%{_licensedir}/%{name}/COPYING

# Plain shell rather than the `%systemd_post` macros, for two reasons: those macros apply the distribution's
# presets, and a preset that enabled this would start reading every request on the machine because somebody
# installed a package. And they are a build dependency this does not otherwise need.
%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
cat <<'SAID'

Flowlight is installed and is not running.

That is on purpose: it reads every HTTPS request on this machine, and starting
that because somebody installed a package would be the wrong way round.

  sudo flowlightd                            watch, in this terminal
  sudo systemctl enable --now flowlightd     watch from now on
  flowlightd budget                          what it is allowed to read, and for how long

SAID

%preun
# Only on removal, not on the removal half of an upgrade: $1 is how many versions will remain.
if [ "$1" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop flowlightd >/dev/null 2>&1 || true
    systemctl disable flowlightd >/dev/null 2>&1 || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
# The database stays. Somebody removing a package is usually not asking for the record of what their machine
# has been doing to be deleted, and RPM has no `purge` to mean that they were. `rm -rf /var/lib/flowlight`
# is one command and it is theirs to type.

%changelog
# Deliberately empty. The changelog lives in the release notes, where it can be read by somebody who has not
# installed the package yet.
