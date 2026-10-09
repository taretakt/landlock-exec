# landlock-exec

Kernel-enforced filesystem confinement for a child command — a ~170-line C file, no capabilities, no
user namespaces, no containers.

```
landlock-exec [--rw DIR]... [--ro DIR]... -- CMD [ARGS...]
```

It applies a Landlock ruleset (allow-list, irreversible) to itself, then `exec`s the child. Anything
outside the named directories is unreachable: no read, no write, no exec, no create, no delete. The
restriction cannot be lifted by the child — Landlock restrict is one-way and enforced by the kernel.
Needs no privileges at all: no root, no `CAP_SYS_ADMIN`, no user namespaces, no seccomp.

## Why

Sandboxing an untrusted command usually means containers (heavy), seccomp (syscall-level, fiddly), or
chroot (root-only, escapable). Landlock is a filesystem LSM that any unprivileged process can invoke
on itself. This tool is the smallest honest wrapper around that: parse `--rw`/`--ro` directories,
build the ruleset, lock yourself down, exec. Everything the child does that touches the filesystem is
either inside an allow-listed directory or fails with `EPERM`/`EACCES`.

## Build

```sh
cc -O2 -Wall -o landlock-exec landlock-exec.c
# or: make
```

## Usage

```sh
# read-only access to ./data, fully isolated elsewhere
./landlock-exec --ro "$(pwd)/data" -- ./analyze.sh

# read-write scratch dir, read-only inputs, no access to anything else
./landlock-exec --rw "$(pwd)/work" --ro "$(pwd)/inputs" -- ./build.sh

# no paths at all: the child can only execute and use inherited fds
./landlock-exec -- ./runs-on-inherited-stdin.sh
```

With no `--rw`/`--ro` paths the child gets no filesystem access beyond what the kernel grants through
inherited file descriptors.

## Requirements

- Linux kernel **5.13+** (Landlock ABI 1). Newer ABIs are used automatically when present:
  ABI 2 adds truncation control, ABI 5 adds ioctl-device control (the `handled_mask()` probe in
  `main`). `uname -r` ≥ 5.13 is the floor; Ubuntu 22.04+ and other mainstream distros ship it.
- No privileges required. This is the point.

## Verification

- `make` builds clean with `-Wall -Wextra` (no warnings).
- `tests/test.sh` builds, then asserts BOTH directions:
  1. allow-listed directory read succeeds;
  2. reading outside the allow-list fails with `Permission denied` (nonzero exit).
  A denial test alone is vacuous: if `restrict_self` fails, the child never runs and "denied" is
  meaningless — so the allow case runs first and must pass. This exact trap is documented in
  `landlock-exec.c`.
- CI runs the suite on every push (ubuntu-latest, kernel ≥ 6.8, Landlock enabled by default).

## Honest limits

- Allow-list only. This is confinement, not a security boundary for hostile code: the child shares
  your UID, network, and kernel. It prevents filesystem access outside the list — nothing more.
- `--rw` grants everything Landlock can express for that tree (write, create, delete, truncate,
  chmod, rename, ioctl-dev on ABI 5). There is no per-path access matrix; keep `--rw` trees small
  and disposable, like build dirs.
- Network, IPC, and process signals are **not** restricted. Pair with seccomp or a network
  namespace if the child is hostile in those dimensions.
- Landlock is irreversible per-process: the child (and any process it spawns) stays confined until
  exit.

## License

MIT — see [LICENSE](LICENSE).