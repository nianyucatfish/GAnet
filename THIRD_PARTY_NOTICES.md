# Third-party notices

GAnet includes or depends on third-party software. Each dependency remains
subject to its own license and copyright notices.

Important direct dependencies include:

- [Tailscale](https://github.com/tailscale/tailscale), including `tsnet`, under
  the BSD 3-Clause License.
- [cryptography](https://github.com/pyca/cryptography), under the Apache
  License 2.0 or BSD 3-Clause License.
- [python-qrcode](https://github.com/lincolnloop/python-qrcode), under the BSD
  License.
- [Pillow](https://github.com/python-pillow/Pillow), under the HPND License.

The Go module dependency graph is recorded in `sidecar/ganet/go.mod` and
`sidecar/ganet/go.sum`. Python dependencies are recorded in `pyproject.toml`.
Release packaging must generate and audit a complete dependency-license bundle
before public distribution. This file is an initial notice, not a replacement
for the complete license texts required by those projects.
