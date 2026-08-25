# GAnet release mirror

These files install the server-side mirror for the public GAnet GitHub release.
The GitHub repository and release are the source of truth; the server publishes a
verified mirror and signs the sidecar manifest with the existing server-only
Ed25519 key.

The synchronizer accepts only published releases that are neither drafts nor
prereleases. It verifies the release tag, provenance commit, GitHub asset sizes,
and `SHA256SUMS.txt`, rejects version downgrades, checks out the exact release
commit, then atomically publishes the sidecar, signed manifest, and state. The
GAnet Python component is distributed as source from the GitHub repository via
git; releases carry only the sidecar binary and its verification metadata. The
synchronizer never prints or copies the signing key.

Expected server paths:

- script: `/opt/ganet-release-sync/ganet_release_sync.py`
- source checkout: `/opt/ganet-release-sync/source/`
- state: `/var/lib/ganet-release-sync/state.json`
- sidecars: `/srv/ganet.gaagent.ai/releases/sidecar/`
- signing key: `/opt/ga-ops/secrets/ganet-sidecar-release-ed25519.pem`

`ganet-release-sync.service` and `ganet-release-sync.timer` are intended for
`/etc/systemd/system/`. The service is a restricted root oneshot because the
existing key is root-only. The timer checks every 15 minutes; a release that
is already mirrored short-circuits without re-downloading, so releases
published under earlier asset rules stay served without revalidation.
