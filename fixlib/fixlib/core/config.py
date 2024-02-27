import requests
import json
from typing import Dict, Tuple, List, Optional, cast, Union
from fixlib.core import fixcore
from fixlib.args import ArgumentParser
from fixlib.jwt import encode_jwt_to_headers
from fixlib.logger import log
from fixlib.types import Json


def default_args(
    fixcore_uri: Optional[str] = None, psk: Optional[str] = None, headers: Optional[Dict[str, str]] = None
) -> Tuple[str, Optional[str], Dict[str, str]]:
    if fixcore_uri is None:
        fixcore_uri = fixcore.http_uri
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)
    if headers is None:
        headers = {}
    if psk is not None:
        encode_jwt_to_headers(headers, {}, psk)
    return fixcore_uri, psk, headers


class ConfigNotFoundError(AttributeError):
    pass


def get_configs(
    fixcore_uri: Optional[str] = None, psk: Optional[str] = None, verify: Optional[str] = None
) -> List[Json]:
    fixcore_uri, psk, headers = default_args(fixcore_uri, psk)

    log.debug("Getting configs")
    r = requests.get(f"{fixcore_uri}/configs", headers=headers, verify=verify)
    if r.status_code == 200:
        return cast(List[Json], r.json())
    raise RuntimeError(f"Error getting configs: {r.content.decode('utf-8')}")


def get_config(
    config_id: str,
    fixcore_uri: Optional[str] = None,
    psk: Optional[str] = None,
    verify: Optional[str] = None,
) -> Tuple[Json, str]:
    fixcore_uri, psk, headers = default_args(fixcore_uri, psk)

    log.debug(f"Getting config {config_id}")

    params = {
        "separate_overrides": "true",  # we don not to have a single config with everything merged into it
        "apply_overrides": "true",  # apply the overrides to the config
        "resolve_env_vars": "true",  # and resolve any environment variables
        "include_raw_config": "true",  # also include the db version of the config
    }

    r = requests.get(
        f"{fixcore_uri}/config/{config_id}",
        headers=headers,
        verify=verify,
        params=params,
    )
    if r.status_code == 200:
        revision = r.headers.get("Fix-Config-Revision", "unknown")
        return r.json(), revision
    elif r.status_code == 404:
        raise ConfigNotFoundError(f"Config {config_id} does not exist")
    raise RuntimeError(f"Error getting config {config_id}: {r.content.decode('utf-8')}")


def set_config(
    config_id: str,
    config: Json,
    fixcore_uri: Optional[str] = None,
    psk: Optional[str] = None,
    verify: Union[str, bool, None] = None,
) -> str:
    fixcore_uri, psk, headers = default_args(fixcore_uri, psk)

    log.debug(f"Storing config {config_id}")
    r = requests.put(
        f"{fixcore_uri}/config/{config_id}",
        json=config,
        headers=headers,
        verify=verify,
    )
    if r.status_code == 200:
        revision = r.headers.get("Fix-Config-Revision", "unknown")
        return revision
    raise RuntimeError(f"Error storing config {config_id}: {r.content.decode('utf-8')}")


def delete_config(
    config_id: str,
    fixcore_uri: Optional[str] = None,
    psk: Optional[str] = None,
    verify: Union[str, bool, None] = None,
) -> bool:
    fixcore_uri, psk, headers = default_args(fixcore_uri, psk)

    log.debug(f"Deleting config {config_id}")
    r = requests.delete(f"{fixcore_uri}/config/{config_id}", headers=headers, verify=verify)
    if r.status_code == 204:
        return True
    raise RuntimeError(f"Error deleting config {config_id}: {r.content.decode('utf-8')}")


def update_config_model(
    model: List[Json],
    fixcore_uri: Optional[str] = None,
    psk: Optional[str] = None,
    verify: Union[str, bool, None] = None,
) -> bool:
    headers = {"Content-Type": "application/json"}
    fixcore_uri, psk, headers = default_args(fixcore_uri, psk, headers=headers)
    model_uri = f"{fixcore_uri}/configs/model"
    model_json = json.dumps(model, indent=4)

    log.debug("Updating config model")
    r = requests.patch(model_uri, data=model_json, headers=headers, verify=verify)
    if r.status_code != 200:
        log.error(r.content)
        raise RuntimeError(f"Failed to update model: {r.content.decode('utf-8')}")
    return True
