# platformd-verifyd

platformd-verifyd is a user-presence verification service for Linux systems — it
challenges a user to prove presence now (fingerprint, face, security key, or
password) and records the result with the platform trust authority. It is a
component of platformd (see `centricd-os`), written in C against libsystemd
(sd-event, sd-varlink, sd-json, sd-login) and libpam, and built with meson.

It is the challenger in platform authentication: platformd-trustd observes and
attests the platform's authentication state, and platformd-verifyd re-establishes
user presence on demand when that state has gone stale. A process may only verify
its own user — the user is taken from the caller's credentials, never a claimed
name.

It provides two programs:

| Program | Role |
| --- | --- |
| `platformd-verifyd` | the daemon; serves the `io.platformd.Verify` Varlink interface |
| `verifyctl` | command-line client to request a verification |

## Requirements

- libsystemd ≥ 257 — sd-event, sd-varlink, sd-json, sd-login
- libpam — drives the configured authentication factors
- meson ≥ 1.1, ninja, and a C11 compiler
- the factor backends you enable — e.g. `fprintd` (fingerprint), Howdy (face), `pam-u2f` (security key)

## Build

```sh
meson setup build --prefix=/usr
ninja -C build
sudo meson install -C build
sudo systemctl enable --now platformd-verifyd.service
```

`--prefix=/usr` installs the daemon under `/usr/lib`, `verifyctl` in `/usr/bin`,
and the PAM stack where PAM looks for it (`/usr/lib/pam.d/platformd-verify`).

## Factors

The factors offered are configured in the `platformd-verify` PAM stack
(`/usr/lib/pam.d/platformd-verify`, overridable under `/etc/pam.d/`). Fingerprint
is enabled by default; face (Howdy) and security key are one line each. Enrol a
fingerprint with `fprintd-enroll` first. Hardware factors are agent-free — the
device is the prompt; a password factor needs the prompt agent, which is not yet
available.

## Documentation

- `platformd-verifyd.service(8)` and `verifyctl(1)` — the manual pages.

## Status

The daemon runs the `platformd-verify` PAM stack for the calling user and, on
success, records the verification with platformd-trustd so the session's freshness
reflects it. Fingerprint, face, and security-key factors work agent-free;
password/PIN needs the prompt agent (a planned addition). The service is requested
over the `io.platformd.Verify` Varlink interface and with `verifyctl`.

## License

LGPL-2.1-or-later
