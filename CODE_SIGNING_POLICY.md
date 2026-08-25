# GAnet code-signing policy

GAnet intends to use SignPath.io free code signing provided by
[SignPath Foundation](https://signpath.org/) for official Windows releases.
Until that enrollment is approved and the workflow verifies an Authenticode
signature, a release must be described as unsigned.

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

- Authenticode signing must use a publicly trusted code-signing service whose
  private key remains in protected service/HSM storage.
- Signing credentials and private keys must never be committed, included in an
  artifact, printed in logs, copied to the release mirror, or exposed to the
  build output.
- A signing request is accepted only for an artifact produced by this
  repository's GitHub-hosted release workflow.
- Release signing requires approval by a designated GAnet maintainer.
- SHA-256 file digests and an RFC 3161 timestamp are required.
- An unsigned Windows sidecar must not be represented as compatible with
  Windows Smart App Control.

## Roles

The current project team is the GitHub repository owner and maintainer,
[nianyucatfish](https://github.com/nianyucatfish):

- **Author and reviewer:** maintains repository code and build scripts and
  reviews contributions from people without direct commit access.
- **Approver:** manually authorizes release signing requests.
- **Build service:** GitHub Actions builds, tests, and records provenance.
- **Signing service:** SignPath verifies the trusted build origin and applies
  the Authenticode signature without exporting the private key.
- **Release mirror:** verifies GitHub Release identity and mirrors the signed
  sidecar; it cannot request or create an Authenticode signature.

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
