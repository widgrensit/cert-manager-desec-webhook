# cert-manager deSEC webhook

A cert-manager DNS-01 solver for [deSEC](https://desec.io). Fork of
[su541/cert-manager-desec-webhook](https://github.com/su541/cert-manager-desec-webhook)
at v1.0.1, maintained for asobi.dev.

Changes from upstream:

- Writes only `_acme-challenge` names. Any other FQDN is refused before the
  deSEC API is called.
- `Present` adds its key to the TXT RRset instead of replacing it, so
  concurrent challenges for the same name (a wildcard and its apex) do not
  overwrite each other. `CleanUp` removes only its own key.
- Current Go, cert-manager and Kubernetes libraries.
- Distroless, non-root image (UID 65532). Run it with `--secure-port=8443`.
- Images are built in CI, scanned with Trivy, signed with cosign (keyless)
  and published to `ghcr.io/widgrensit/cert-manager-desec-webhook`. Deploy by
  digest.

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

Scope the token to `_acme-challenge` TXT records with deSEC token policies.

Go reads the system trust store unless `SSL_CERT_FILE` and `SSL_CERT_DIR`
both point at a mounted bundle. Pin them to the roots deSEC chains to.

## Verifying an image

```shell
cosign verify ghcr.io/widgrensit/cert-manager-desec-webhook@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/widgrensit/cert-manager-desec-webhook/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Development

```shell
make vet test
make build
```

## Licence

MPL-2.0, as upstream. See [LICENSE](LICENSE).
