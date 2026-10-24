# cert-manager deSEC webhook

A cert-manager DNS-01 solver for [deSEC](https://desec.io). Fork of
[su541/cert-manager-desec-webhook](https://github.com/su541/cert-manager-desec-webhook)
at v1.0.1, maintained for asobi.dev.

Changes from upstream:

- Writes only `_acme-challenge` names. Any other FQDN is refused before the
  deSEC API is called.
- `Present` adds its key to the TXT RRset instead of replacing it, so
  concurrent challenges for the same name (a wildcard and its apex) do not
  overwrite each other. `CleanUp` removes only its own key. Both run under one
  lock, so the webhook must run as a single replica.
- Current Go, cert-manager and Kubernetes libraries.
- Distroless, non-root image (UID 65532). Run it with `--secure-port=8443`.
- Images are built in CI, scanned with Trivy, signed with cosign (keyless)
  and published to `ghcr.io/widgrensit/cert-manager-desec-webhook`. Deploy by
  digest. A release is pushed by digest, scanned, signed, and only then given
  its version tag.

## Configuration

Set `GROUP_NAME` on the webhook and reference a Secret holding the deSEC token
from the issuer:

```yaml
solvers:
  - dns01:
      webhook:
        groupName: <GROUP_NAME>
        solverName: desec
        config:
          apiKeySecretRef:
            name: desec-io-token
            key: token
```

deSEC token policies match subnames exactly, with no patterns, so a token
cannot be limited to `_acme-challenge` names. Grant TXT writes on the zone,
deny writes to the TXT records that already exist (apex SPF, `_dmarc`, DKIM
selectors), and restrict `allowed_subnets` to the webhook's egress IP. TXT at
new names stays writable with the token itself; the webhook refuses them.

Go reads the system trust store unless `SSL_CERT_FILE` and `SSL_CERT_DIR`
both point at a mounted bundle. Pin them to the roots deSEC chains to.

## Verifying an image

```shell
cosign verify ghcr.io/widgrensit/cert-manager-desec-webhook@sha256:<digest> \
  --certificate-identity https://github.com/widgrensit/cert-manager-desec-webhook/.github/workflows/ci.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Development

```shell
make vet test
make build
```

## Licence

MPL-2.0, as upstream. See [LICENSE](LICENSE).
