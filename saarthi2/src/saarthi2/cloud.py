"""Cloud provisioning — spin up scan boxes via each provider's official CLI.

Each provider maps to a ``provision``/``destroy`` command template driven by the
provider's own CLI (doctl/aws/gcloud/linode-cli/az). This keeps Saarthi 2.0
credential-free: it shells out to a CLI you have already authenticated. After
provisioning, target the box with a ``tool`` step using ``runner: ssh``.

NOTE: these require the provider CLI installed + authenticated to actually run.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudProvider:
    name: str
    cli: str
    provision: str
    destroy: str
    requires: str


_PROVIDERS: tuple[CloudProvider, ...] = (
    CloudProvider(
        "digitalocean", "doctl",
        "doctl compute droplet create {name} --size {size} --image {image} "
        "--region {region} --ssh-keys {ssh_key} --wait "
        "--format PublicIPv4 --no-header",
        "doctl compute droplet delete {name} -f",
        "doctl + DIGITALOCEAN_ACCESS_TOKEN",
    ),
    CloudProvider(
        "aws", "aws",
        "aws ec2 run-instances --image-id {image} --instance-type {size} "
        "--key-name {ssh_key} --tag-specifications "
        "'ResourceType=instance,Tags=[{{Key=Name,Value={name}}}]' "
        "--query Instances[0].InstanceId --output text",
        "aws ec2 terminate-instances --instance-ids {instance_id}",
        "aws CLI + credentials",
    ),
    CloudProvider(
        "gcp", "gcloud",
        "gcloud compute instances create {name} --machine-type {size} "
        "--image-family {image} --zone {region} --format value(networkInterfaces[0]."
        "accessConfigs[0].natIP)",
        "gcloud compute instances delete {name} --zone {region} -q",
        "gcloud CLI + project/auth",
    ),
    CloudProvider(
        "linode", "linode-cli",
        "linode-cli linodes create --label {name} --type {size} --image {image} "
        "--region {region} --root_pass {root_pass} --text --no-headers "
        "--format ipv4",
        "linode-cli linodes delete {instance_id}",
        "linode-cli + token",
    ),
    CloudProvider(
        "azure", "az",
        "az vm create -g {resource_group} -n {name} --image {image} "
        "--size {size} --admin-username {user} --generate-ssh-keys "
        "--query publicIpAddress -o tsv",
        "az vm delete -g {resource_group} -n {name} --yes",
        "az CLI + subscription",
    ),
)

CLOUD_PROVIDERS: dict[str, CloudProvider] = {p.name: p for p in _PROVIDERS}


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(template: str, params: dict) -> str:
    return template.format_map(_Blank(params)).strip()


def render_provision_command(provider: str, params: dict) -> str:
    p = CLOUD_PROVIDERS.get(provider)
    if p is None:
        raise ValueError(f"unknown cloud provider {provider!r}; {sorted(CLOUD_PROVIDERS)}")
    merged = {"size": "", "image": "", "region": "", "ssh_key": "", **params}
    return _render(p.provision, merged)


def render_destroy_command(provider: str, params: dict) -> str:
    p = CLOUD_PROVIDERS.get(provider)
    if p is None:
        raise ValueError(f"unknown cloud provider {provider!r}; {sorted(CLOUD_PROVIDERS)}")
    return _render(p.destroy, params)


def cloud_catalog() -> list[dict]:
    return [
        {"name": p.name, "cli": p.cli, "requires": p.requires}
        for p in _PROVIDERS
    ]
