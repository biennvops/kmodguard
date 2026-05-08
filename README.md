# kmodguard

`kmodguard` is a kernel module whilelisting system.

https://github.com/user-attachments/assets/e2bdf68c-5508-49a3-9e8d-3bafef152cb6


## Why `kmodguard?`

- You don't want to maintain a `modprobe.d` blacklist.
- You don't like setting `kernel.modules_disabled = 1` because you want loadable modules support without rebooting.

## Components

- `kmodctl`: operator CLI (`init`, `start`, `stop`, `status`, `hook`, `allow`, `remove`, `apply`)
- `kmodguard`: daemon that evaluates module load requests against policy
- `kmodguard-core`: shared policy schema, alias resolver, and decision engine

## Policy file

Default policy path: `/etc/kmodguard/policy.toml`.

Policy supports canonical module names and aliases:

- `allow.modules`: canonical modules
- `allow.aliases`: accepted alias tokens/patterns
- `deny.modules`: explicit deny entries
- `mode`: `enforce` or `audit`

## Quick start

1. Build:

   `make build`

2. Install:

   `sudo make install`

3. Initialize policy (required):

   `sudo kmodctl init --output /etc/kmodguard/policy.toml`

4. Reload and start service:

   `sudo systemctl daemon-reload && sudo systemctl enable --now kmodguard.service`

## Runtime policy edits

- `kmodctl allow <module>`: allow module immediately in daemon memory.
- `kmodctl remove <module>`: remove module immediately in daemon memory.
- `kmodctl apply`: persist current daemon runtime policy to `/etc/kmodguard/policy.toml`.

Notes:
- `allow/remove` require daemon socket access.
- policy file is unchanged until `kmodctl apply`.

## Install paths

- `kmodguard` -> `/usr/libexec/kmodguard/kmodguard`
- `kmodctl` -> `/usr/bin/kmodctl`
- `kmodguard.service` -> `/etc/systemd/system/kmodguard.service`
- `kmodguard-hook` -> `/usr/libexec/kmodguard/kmodguard-hook`

Staging example (packaging):

`make build && make DESTDIR=/tmp/kmodguard-pkg install`

## Safety behavior

- `start` stores existing `/proc/sys/kernel/modprobe` at `/run/kmodguard/original_modprobe`.
- `stop` restores it.
- The hook (`kmodctl hook`) is fail-closed: if the daemon socket is unreachable, module loads are denied and the event is logged via syslog. There is no local-policy fallback.
- Denied requests are reported through daemon stderr (captured by journald under systemd).

### Trust boundary

- The daemon control socket (`/run/kmodguard/daemon.sock`) is created `0600` inside a `0755` runtime directory. The daemon also enforces `SO_PEERCRED` and rejects any connection from a non-root peer with `ERR unauthorized`.
- `kmodctl allow|remove|apply` therefore only work when invoked as root and only when the daemon is running.

## Recovery

If the daemon is down and the handler path is stuck, manually restore:

`echo /usr/bin/modprobe > /proc/sys/kernel/modprobe`

Or use `kmodctl disarm --force` which falls back to `/usr/bin/modprobe` when the saved state file is missing.

## License

This project is licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only). See `LICENSE` for the full text.
