# platformd-verifyd

platformd-verifyd verifies the presence of the calling user through a
configured PAM stack. It associates each request with an active, local,
logind-reported unlocked user session. Authentication responses are exchanged
with a systemd password agent and are never returned to the client. A
successful result may be submitted to platformd-trustd when it is available.

## Requirements

- libsystemd 258 or newer
- Linux PAM
- systemd-logind
- a compatible systemd password presenter for password or PIN authentication
- Meson 1.1 or newer
- a C11 compiler

## Build

```sh
meson setup build --prefix=/usr
meson compile -C build
meson test -C build
sudo meson install -C build
sudo systemctl enable --now platformd-verifyd.service
```

The installed PAM service is `platformd-verify`. The default stack uses
`pam_fprintd.so`. Administrators may override the vendor stack in
`/etc/pam.d/platformd-verify`.

`-Dpamvendordir=PATH` selects the vendor PAM directory. The default is taken
from `pam.pc`, with `${prefix}/lib/pam.d` as the fallback.

The password interface is per-user, not per-session. PAM informational messages
are recorded in the journal. A polkit authentication agent does not implement
this password interface.

See `platformd-verifyd.service(8)` and `verifyctl(1)` for details.

## License

LGPL-2.1-or-later
