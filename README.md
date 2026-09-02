# GAnet

GAnet is the desktop user center and device-interconnect component for
GenericAgent. Its user center runs independently; access to GenericAgent's
computer atomic tools is an explicit, validated host binding rather than an
installation inside the GenericAgent source tree.

> Current status: standalone component and audited release pipeline baseline.
> Windows (amd64) and macOS (arm64, amd64) are the supported desktop platforms.
> The Python component is distributed as source from this repository via git;
> tagged GitHub Releases publish the sidecar binaries and their verification
> metadata. The final end-user download disclaimer is still being prepared.

## Repository layout

```text
ganet/                 Python package and local user center
sidecar/ganet/         auditable tsnet sidecar source and tests
ganet.cmd              Windows launcher
ganet.sh               macOS/Linux launcher (ganet.command: Finder double-click)
```

## Run from source

Python 3.10 or newer is required for local development:

```text
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\python -m ganet
```

An installed component is a git clone of this repository. It runs under the
GenericAgent Python recorded by `configure-host`: the lightweight dependencies
(`cryptography`, `Pillow`, `qrcode`) are installed into that interpreter, and
`ganet.cmd` (Windows) or `ganet.sh` (macOS) reads the bound interpreter from
`~/.genericagent/ganet/ga_python.cmd` / `ga_python.sh`, so it can be
double-clicked from any working directory without a PATH or `PYTHONPATH` setup.
Updates are `git pull`, which also lets users merge their own local changes.

The component exposes a machine-readable identity check, run with any Python
from the checkout root:

```text
python -m ganet inspect-component --json
```

A successful inspection verifies the launcher, source package layout, version,
and current component root. `configure-host` and a normal user-center launch
atomically refresh the non-secret discovery record at
`~/.genericagent/ganet/component.json`. GenericAgent can use that record to find
a previously installed or moved component, but must still call the identity
check before trusting the recorded path. The clone location is chosen at
install time (GenericAgent defaults to `~/.genericagent/components/GAnet`); the
component remains movable, and starting it from its new location refreshes the
record.

## State and trust boundaries

- Package files are resolved from the current GAnet package location and can be
  moved together.
- GAuth identity remains under `~/.genericagent/gauth/`.
- GAnet state and the explicit GenericAgent host binding remain under
  `~/.genericagent/ganet/`.
- The sidecar binary, protected state, and logs remain under
  `%LOCALAPPDATA%\GenericAgent\GAnet\` on Windows and
  `~/Library/Application Support/GenericAgent/GAnet/` on macOS; the macOS login
  agent is `~/Library/LaunchAgents/ai.gaagent.ganet-sidecar.plist`.
- A bound GenericAgent root is used only for the original computer atomic tools;
  it is not required to open the user center.

Tokens, enrollment grants, pairing messages, QR payloads, SSH private keys, and
user state must never be committed or included in release archives. Pairing
still requires the phone scan and confirmation on the current PC.

## Sidecar development

From `sidecar/ganet/`:

```text
go test ./...
go build -o ganet-sidecar.exe .
```

Development builds report version `dev`. Release builds will inject the exact
Git tag and commit using Go linker flags, then publish checksums and build
provenance.

## Code signing

The Windows sidecar is covered by the repository's
[code-signing policy](CODE_SIGNING_POLICY.md). Checksums, release provenance,
and the server-signed update manifest remain separate layers of verification;
they do not replace Windows Authenticode signing.

## License

GAnet is licensed under the MIT License. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Third-party components retain
their own licenses.
