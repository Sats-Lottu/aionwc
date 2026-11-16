# Publish aionwc to PyPI

## Register the Trusted Publisher

For the first release, add a GitHub pending publisher from your
[PyPI publishing settings](https://pypi.org/manage/account/publishing/).

| PyPI field | Value |
| --- | --- |
| PyPI project name | `aionwc` |
| Owner | `Sats-Lottu` |
| Repository name | `aionwc` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

PyPI creates the project on the first successful upload. The workflow
authenticates through GitHub Actions OIDC.

## Verify and publish a release

1. Run **Build and publish to PyPI** manually from `main` to verify the
   tests and distributions. This run stops after validation.
2. Confirm the release version in `pyproject.toml` and choose the commit
   containing that version. Publish a GitHub Release with its matching
   tag, such as `v0.1.0` for version `0.1.0`.
3. Check the workflow run and confirm that the wheel and source
   distribution appear on the [PyPI project page](https://pypi.org/project/aionwc/).
