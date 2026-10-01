# The window, as an RPM — and unlike the daemon's, this one is built where it will run.
#
# The daemon is statically linked, so the machine that compiles it has nothing to do with the machine that runs
# it. The window is the opposite: it links against the system's GTK, the system's libadwaita and the system's
# glibc, so one built on Ubuntu 24.04 does not start on a distribution whose glibc is older. The answer is to
# compile it inside a container of each distribution, and let RPM's own dependency scan record what it found
# there — `libgtk-4.so.1()(64bit)` and the rest, resolved against the libraries that were actually present.
#
# Which is why `AutoReqProv` is left alone here. On the daemon it is turned off because there is nothing to
# find; here the scan is the entire point.

Name:           flowlight-gui
Version:        %{version}
# Which distribution built this is part of what it is: two files called `flowlight-gui-0.5.5-1.x86_64.rpm`
# that link against different libraries would be two files nobody can tell apart. `build.sh` fills it in from
# `/etc/os-release` inside the container that did the building.
#
# `built_on` rather than `suffix`, which is a built-in macro name that newer rpm refuses to let `--define`
# shadow — with the message `Macro %suffix is a built-in`, which is how this was found.
Release:        1%{?built_on}
Summary:        The window for Flowlight
License:        GPL-3.0-only
URL:            https://github.com/xinbetween/flowlight-linux
BuildArch:      %{architecture}

# The window talks to the daemon over its socket and is useless without it. Same version, because the two speak
# a protocol that is not promised to be stable between releases.
Requires:       flowlight = %{version}

%global source_date_epoch_from_changelog 0

%description
A GTK 4 window that runs as you and talks to the daemon over a Unix socket with
an owner and a mode.

Separate from the daemon because a server has no reason to pull in GTK to watch
its own traffic, and because the daemon is statically linked and travels while
the window is linked against this distribution's own libraries and does not.

It shows what was seen, what was refused, what could not be read, and what each
feature would do before it is switched on. The privileges, the probes and the
database are the daemon's.

%install
rm -rf %{buildroot}
install -D -m 755 %{built}/flowlight %{buildroot}%{_bindir}/flowlight
install -D -m 644 %{licence} %{buildroot}%{_licensedir}/%{name}/COPYING

%files
%{_bindir}/flowlight
%{_licensedir}/%{name}/COPYING
