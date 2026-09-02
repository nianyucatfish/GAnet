# GAnet code-signing policy

Official Windows GAnet releases are distributed without Authenticode signing,
a deliberate decision (2026-08-27) consistent with GenericAgent Desktop.
Releases must be described as unsigned and must not be represented as
compatible with Windows Smart App Control. Release integrity is provided by
the build and mirror controls below.

## Scope

Official Windows GAnet releases are built only by the public GitHub Actions
workflow in this repository. The Windows sidecar is the executable covered by
this policy and the only binary a release publishes. The Python component is
distributed as source from this repository via git and ships no executable of
its own.

## Source and build integrity

- Release tags use `v<major>.<minor>.<patch>` and must point to `main` history.
- GitHub Actions runs the Python and Go test suites before producing artifacts.
- Release builds embed the tag version and exact Git commit in the sidecar.
- `SHA256SUMS.txt`, `provenance.json`, and `sidecar-version.json` bind every
  published artifact to that build identity.
- The public server imports only published, non-draft, non-prerelease releases,
  verifies their provenance and checksums, and signs its own canonical update
  manifest with a separate server-only Ed25519 key.

## Signing controls

- The server's Ed25519 manifest key is the only release-signing credential; it
  stays in restricted server storage, is used only by the mirror's sync
  script, and must never be read, printed, downloaded, or copied elsewhere.
- Signing credentials and private keys must never be committed, included in an
  artifact, printed in logs, or exposed to the build output.

## macOS code identity (not a trust signature)

macOS sidecars are not signed with an Apple Developer ID and are not
notarized; like the Windows release they must be described as unsigned in the
Gatekeeper sense. They do carry a code signature made with a **self-signed
GAnet certificate** held only in the GitHub Actions secret
`GANET_MACOS_SIGNING_PEM`, applied in the release workflow with a pinned
`rcodesign`, with binary identifier `ai.gaagent.ganet-sidecar`.

The purpose is identity continuity, not trust: macOS privacy permissions
(screen recording) are keyed on the executable's designated code requirement.
An ad-hoc signature changes with every build, so each upgrade would re-prompt
the user; the stable certificate makes the requirement
`identifier "ai.gaagent.ganet-sidecar" and certificate leaf = H"…"` identical
across releases, and a permission granted once survives upgrades.

- The certificate is valid until 2036-08-30. Rotating it costs every macOS user
  exactly one new permission prompt at the next upgrade; rotate only when the
  key is suspected of compromise.
- The private key must never be committed, printed, or copied out of the
  secret store; an offline backup is kept by the approver.
- A release build fails rather than publishing macOS binaries with an
  unstable ad-hoc identity when the secret is missing.

## Roles

The current project team is the GitHub repository owner and maintainer,
[nianyucatfish](https://github.com/nianyucatfish):

- **Author and reviewer:** maintains repository code and build scripts and
  reviews contributions from people without direct commit access.
- **Approver:** manually publishes releases.
- **Build service:** GitHub Actions builds, tests, and records provenance.
- **Release mirror:** verifies GitHub Release identity, mirrors the sidecar,
  and signs the canonical update manifest with the server-only Ed25519 key.

## Privacy

GAnet communicates with GAuth, the GAnet control plane, the signed release
service, and explicitly paired devices only when the user requests the
corresponding account, update, enrollment, pairing, or device-access operation.
Release builds do not contain advertising or unrelated telemetry.

## Revocation and incident response

If a signing credential, release workflow, or published artifact is suspected
of compromise, maintainers will stop new releases, revoke or disable the
relevant signing authorization, mark affected releases as withdrawn, rotate
credentials where applicable, and publish a replacement release only after the
source and build provenance have been re-audited.
