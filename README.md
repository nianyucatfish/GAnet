# GAnet

GAnet is the desktop user center and device-interconnect component for
GenericAgent. Its user center runs independently; access to GenericAgent's
computer atomic tools is an explicit, validated host binding rather than an
installation inside the GenericAgent source tree.

> Current status: local development baseline. Windows is the only supported
> desktop platform in this first pass. Public release packaging and the final
> download disclaimer are not complete yet.

## Repository layout

```text
ganet/                 Python package and local user center
sidecar/ganet/         auditable tsnet sidecar source and tests
ganet.cmd              Windows launcher
```

## Run from source

Python 3.10 or newer is required for local development:

```text
python -m venv .venv
.venv\Scripts\python -m pip install -e .
ganet.cmd
```

The published GAnet component will include its own runtime under `runtime/`,
so normal use will not require PATH, `PYTHONPATH`, `GANET_HOME`, or the Python
interpreter bound for GenericAgent tools. `ganet.cmd` resolves paths relative
to its own location and can therefore be launched from an unrelated working
directory.

## State and trust boundaries

- Package files are resolved from the current GAnet package location and can be
  moved together.
- GAuth identity remains under `~/.genericagent/gauth/`.
- GAnet state and the explicit GenericAgent host binding remain under
  `~/.genericagent/ganet/`.
- The Windows sidecar binary, protected state, and logs remain under
  `%LOCALAPPDATA%\GenericAgent\GAnet\`.
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

## License

GAnet is licensed under the MIT License. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Third-party components retain
their own licenses.
