# Native Linux packages

Proper Debian, Fedora and Arch packages for the Mintlayer node software:
systemd integration, hardware-wallet udev rules, man pages, conffiles,
declared library dependencies, and lint/install validation — for both
amd64/x86_64 and arm64/aarch64.

The same scripts run in CI (`.github/workflows/release_linux.yml`) and
locally, inside the same container images, so a green local run means the
tagged release build will behave identically.

## Packages

| Package | Contents |
|---|---|
| `mintlayer-node` | node-daemon, wallet-rpc-daemon, api-web-server, api-blockchain-scanner-daemon, dns-server, wallet-cli, wallet-address-generator + systemd units, sysusers, preset, udev rules, man pages, `/etc/mintlayer` conffiles |
| `mintlayer-node-gui` | node-gui + hicolor icons + desktop entry + man page |

They are produced as `.deb` (Debian), `.rpm` (Fedora) and `.pkg.tar.zst`
(Arch) packages with identical payloads.

### What the packages set up

- **systemd template units**, one instance per chain:
  - `mintlayer-node@{mainnet,testnet}.service` — explicit unit: runs the node
    as the `mintlayer` system user with `--datadir /var/lib/mintlayer/<chain>`
  - `mintlayer-wallet-rpc@.service`, `mintlayer-api-web-server@.service`,
    `mintlayer-api-blockchain-scanner@.service`, `mintlayer-dns-server@.service`
    — driven by `ARGS` from `/etc/mintlayer/<chain>/<service>.env` (see the
    shipped templates and each tool's `--help`)
  - all units ship hardening (`ProtectSystem=strict`, `NoNewPrivileges`, …)
    and log to the journal
- **Preset policy**: only `mintlayer-node@mainnet.service` is enabled on
  install; everything else is opt-in. On Debian it is applied by postinst
  (`systemctl preset`), on Fedora via `90-mintlayer.preset` +
  `%systemd_post`.
- **System user** `mintlayer` via `sysusers.d` (+ fallback useradd in the deb
  postinst). The home directory `/var/lib/mintlayer` holds chain state.
- **udev rules** (`51-mintlayer.rules`): Ledger and Trezor hidraw access via
  `uaccess`, shipped with `mintlayer-node` (used by wallet-cli and, when the
  recommended `mintlayer-node` package is installed, by the GUI).
- **Dependencies**: computed from the binaries with `dpkg-shlibdeps` (deb) /
  RPM soname autorequires / `pacman -F` lookups (Arch); the deb additionally
  gets an `ldd` gate that fails the build if any library is unresolved.

### Arch-specific notes

- The Arch images published by the Arch project are amd64-only, so the
  aarch64 package is repackaged cross-target from the amd64 container (like
  the local cross-target rpm builds): binaries are shipped unstripped, man
  pages are stubs and the dependency list comes from a static map (see
  `packaging/arch/build.sh`). The x86_64 package is fully arch-matched.
- Arch convention is to not start services from package scripts: the install
  scriptlet applies the preset policy (enabling `mintlayer-node@mainnet`)
  but does not start the unit; start it with
  `systemctl start mintlayer-node@mainnet.service`.
- The GUI package declares `mintlayer-node` as an `optdepends` (Arch's
  equivalent of deb/rpm Recommends); install it for the udev rules.
- The packages are not published to the AUR; install a release artifact
  directly with `sudo pacman -U Mintlayer_Node_linux_<version>_<arch>.pkg.tar.zst`.

## Local testing (before tagging a release)

The release workflow only triggers on tags, so validate locally first:

```sh
packaging/test-local.sh                 # full matrix: both arches, deb+rpm, smoke tests
packaging/test-local.sh --quick         # amd64/x86_64 only, no qemu
packaging/test-local.sh --skip-build    # reuse existing target/*/release binaries
packaging/test-local.sh --check         # preflight only (docker, binfmt, images)
```

Requirements: docker, and (for the arm64 legs on an x86_64 host) qemu binfmt:

```sh
docker run --privileged --rm multiarch/qemu-user-static --reset -p yes
```

The script builds binaries with the exact CI flags
(`cargo build --release --locked --features trezor,ledger`), then:

1. assembles debs inside `debian:12` (arm64 via `--platform linux/arm64`)
2. assembles rpms inside `fedora:latest` (`--target x86_64` and `aarch64`;
   repackaging only, no emulation needed for rpm)
3. assembles Arch packages inside `archlinux:base` (x86_64 arch-matched;
   aarch64 cross-targeted from the amd64 container — Arch publishes no arm64
   images)
4. runs lintian / rpmlint / namcap inside the same containers
5. installs each package in a **fresh** container and verifies: system user,
   binaries run (`--help`), `systemd-analyze verify` on all units, preset,
   conffiles, icons, desktop file (the Arch arm64 packages skip the
   install step: pacman refuses foreign-architecture packages)
6. checks the artifact names against the globs `release.yml` uploads

A final summary matrix prints; exit code 0 = safe to tag.

Note: building the aarch64 *binaries* locally requires the arm64
cross-toolchain and arm64 system libraries (as CI sets up). Without them, run
`--quick` locally and let the `workflow_dispatch` dry-run of
`release_linux.yml` (Actions tab) exercise the arm64 legs in CI before
tagging.

## CI integration

`release_linux.yml` calls the same builders per matrix arch:

- deb: `docker run --platform linux/$ARCH debian:12 packaging/deb/build.sh …`
- rpm: `docker run fedora:latest packaging/rpm/build.sh …`
- arch pkg: `docker run $ARCH_IMAGE packaging/arch/build.sh …` (amd64-only
  images; see the Arch-specific notes above)
- smoke: fresh-container installs via `packaging/checks/smoke-*.sh`

Artifact names are unchanged (`Mintlayer_Node_linux_<version>_<arch>.deb/rpm`,
`Mintlayer_Node_GUI_linux_<version>_<arch>.deb/rpm`, plus the
`.pkg.tar.zst` variants) so `release.yml` attaches them exactly as before.
New: GUI + node rpms are produced for both arches (previously rpm was
x86_64-only), and `workflow_dispatch` allows a no-tag dry run.

## Layout

```
packaging/
  common/            assets shared by all package formats
    systemd/         template units (one per daemon)
    sysusers/        mintlayer system user definition
    udev/            Ledger/Trezor hidraw rules
    preset/          default-enable policy (mainnet node only)
    env/             per-service environment templates (/etc/mintlayer/<chain>/)
    applications/    .desktop entry for the GUI
  deb/               control template, maintscripts, changelog, build.sh
  rpm/               spec templates, build.sh
  arch/              PKGBUILD templates, install scriptlet, build.sh
  checks/            smoke-deb.sh, smoke-rpm.sh, smoke-arch.sh, verify-artifacts.sh
  make-icons.sh      hicolor icon set generator
  test-local.sh      full local replica of the release pipeline
  dist/              build output (gitignored)
```
