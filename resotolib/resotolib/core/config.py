import requests
import json
from typing import Dict, Tuple, List, Optional
from resotolib.core import resotocore
from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.logger import log


def default_args(resotocore_uri: str = None, psk: str = None, headers=None) -> Tuple[str, str, Dict[str, str]]:
    if resotocore_uri is None:
        resotocore_uri = resotocore.http_uri
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)
    if headers is None:
        headers = {}
    if psk is not None:
        encode_jwt_to_headers(headers, {}, psk)
    return resotocore_uri, psk, headers


class ConfigNotFoundError(AttributeError):
    pass


def get_configs(resotocore_uri: str = None, psk: str = None, verify: Optional[str] = None) -> List:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug("Getting configs")
    r = requests.get(f"{resotocore_uri}/configs", headers=headers, verify=verify)
    if r.status_code == 200:
        return r.json()
    raise RuntimeError(f"Error getting configs: {r.content.decode('utf-8')}")


def get_config(
    config_id: str,
    resotocore_uri: str = None,
    psk: str = None,
    verify: Optional[str] = None,
) -> Tuple[Dict, str]:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Getting config {config_id}")
    r = requests.get(f"{resotocore_uri}/config/{config_id}", headers=headers, verify=verify)
    if r.status_code == 200:
        revision = r.headers.get("Resoto-Config-Revision", "unknown")
        return r.json(), revision
    elif r.status_code == 404:
        raise ConfigNotFoundError(f"Config {config_id} does not exist")
    raise RuntimeError(f"Error getting config {config_id}: {r.content.decode('utf-8')}")


def set_config(
    config_id: str,
    config: Dict,
    resotocore_uri: str = None,
    psk: str = None,
    verify: Optional[str] = None,
) -> str:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Storing config {config_id}")
    r = requests.put(
        f"{resotocore_uri}/config/{config_id}",
        json=config,
        headers=headers,
        verify=verify,
    )
    if r.status_code == 200:
        revision = r.headers.get("Resoto-Config-Revision", "unknown")
        return revision
    raise RuntimeError(f"Error storing config {config_id}: {r.content.decode('utf-8')}")


def delete_config(
    config_id: str,
    resotocore_uri: str = None,
    psk: str = None,
    verify: Optional[str] = None,
) -> bool:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Deleting config {config_id}")
    r = requests.delete(f"{resotocore_uri}/config/{config_id}", headers=headers, verify=verify)
    if r.status_code == 204:
        return True
    raise RuntimeError(f"Error deleting config {config_id}: {r.content.decode('utf-8')}")


def update_config_model(
    model: List,
    resotocore_uri: str = None,
    psk: str = None,
    verify: Optional[str] = None,
) -> bool:
    headers = {"Content-Type": "application/json"}
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk, headers=headers)
    model_uri = f"{resotocore_uri}/configs/model"
    model_json = json.dumps(model, indent=4)

    log.debug("Updating config model")
    r = requests.patch(model_uri, data=model_json, headers=headers, verify=verify)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to update model: {r.content}")
