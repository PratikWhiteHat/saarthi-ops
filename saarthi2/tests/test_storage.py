"""Cloud object-storage command rendering."""

from __future__ import annotations

import pytest

from saarthi2.storage import (
    STORAGE_PROVIDERS,
    render_download_command,
    render_upload_command,
    storage_catalog,
)


def test_s3_upload() -> None:
    cmd = render_upload_command("s3", {"src": "/tmp/report.md", "bucket": "loot"})
    assert cmd == "aws s3 cp /tmp/report.md s3://loot/report.md"


def test_s3_compatible_endpoint() -> None:
    cmd = render_upload_command(
        "s3c", {"src": "a.json", "bucket": "b", "endpoint": "https://minio:9000", "dest": "x.json"}
    )
    assert cmd.startswith("aws --endpoint-url https://minio:9000 s3 cp a.json s3://b/x.json")


def test_gcs_and_azure_upload() -> None:
    assert render_upload_command("gcs", {"src": "a", "bucket": "b"}) == "gsutil cp a gs://b/a"
    az = render_upload_command("azure", {"src": "a", "bucket": "c", "account": "acct"})
    assert "az storage blob upload" in az and "--account-name acct" in az


def test_download_command() -> None:
    cmd = render_download_command("s3", {"src": "/tmp/out", "bucket": "loot", "dest": "k"})
    assert cmd == "aws s3 cp s3://loot/k /tmp/out"


def test_missing_args_and_unknown_provider() -> None:
    with pytest.raises(ValueError, match="requires 'src'"):
        render_upload_command("s3", {"bucket": "b"})
    with pytest.raises(ValueError, match="requires 'bucket'"):
        render_upload_command("s3", {"src": "a"})
    with pytest.raises(ValueError, match="unknown storage provider"):
        render_upload_command("nope", {"src": "a", "bucket": "b"})


def test_catalog() -> None:
    names = {p["name"] for p in storage_catalog()}
    assert names == set(STORAGE_PROVIDERS)
    assert {"s3", "gcs", "azure"} <= names
