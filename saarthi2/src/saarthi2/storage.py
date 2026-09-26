"""Cloud object-storage upload/download — via each provider's authenticated CLI.

Mirrors :mod:`saarthi2.cloud`: credential-free, shelling out to a CLI you have
already authenticated (aws/gsutil/az). ``s3c`` targets any S3-compatible endpoint
(MinIO/Wasabi/R2) via ``aws --endpoint-url``. Use to ship a run snapshot/report
off-box to durable storage after a scan.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StorageProvider:
    name: str
    cli: str
    upload: str
    download: str
    requires: str


_PROVIDERS: tuple[StorageProvider, ...] = (
    StorageProvider(
        "s3", "aws",
        "aws s3 cp {src} s3://{bucket}/{dest}",
        "aws s3 cp s3://{bucket}/{dest} {src}",
        "aws CLI + credentials",
    ),
    StorageProvider(
        "s3c", "aws",
        "aws --endpoint-url {endpoint} s3 cp {src} s3://{bucket}/{dest}",
        "aws --endpoint-url {endpoint} s3 cp s3://{bucket}/{dest} {src}",
        "aws CLI + S3-compatible endpoint (MinIO/Wasabi/R2)",
    ),
    StorageProvider(
        "gcs", "gsutil",
        "gsutil cp {src} gs://{bucket}/{dest}",
        "gsutil cp gs://{bucket}/{dest} {src}",
        "gsutil + gcloud auth",
    ),
    StorageProvider(
        "azure", "az",
        "az storage blob upload --account-name {account} --container-name {bucket} "
        "--name {dest} --file {src} --overwrite",
        "az storage blob download --account-name {account} --container-name {bucket} "
        "--name {dest} --file {src}",
        "az CLI + storage account",
    ),
)

STORAGE_PROVIDERS: dict[str, StorageProvider] = {p.name: p for p in _PROVIDERS}


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(template: str, params: dict) -> str:
    return template.format_map(_Blank(params)).strip()


def render_upload_command(provider: str, params: dict) -> str:
    p = STORAGE_PROVIDERS.get(provider)
    if p is None:
        raise ValueError(f"unknown storage provider {provider!r}; {sorted(STORAGE_PROVIDERS)}")
    if not str(params.get("src", "")).strip():
        raise ValueError("upload requires 'src'")
    if not str(params.get("bucket", "")).strip():
        raise ValueError("upload requires 'bucket'")
    # Default the remote object name to the source's basename.
    merged = {"dest": str(params.get("src", "")).rsplit("/", 1)[-1], **params}
    return _render(p.upload, merged)


def render_download_command(provider: str, params: dict) -> str:
    p = STORAGE_PROVIDERS.get(provider)
    if p is None:
        raise ValueError(f"unknown storage provider {provider!r}; {sorted(STORAGE_PROVIDERS)}")
    return _render(p.download, params)


def storage_catalog() -> list[dict]:
    return [{"name": p.name, "cli": p.cli, "requires": p.requires} for p in _PROVIDERS]
