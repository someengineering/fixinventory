import requests
from typing import Dict, Tuple
from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.logging import log


def default_args(
    resotocore_uri: str = None, psk: str = None, headers=None
) -> Tuple[str, str, Dict[str, str]]:
    if resotocore_uri is None:
        resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", "").strip("/")
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)
    if headers is None:
        headers = {}
    if psk is not None:
        encode_jwt_to_headers(headers, {}, psk)
    return resotocore_uri, psk, headers


class ConfigNotFoundError(Exception):
    pass


def get_configs(resotocore_uri: str = None, psk: str = None) -> Dict:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug("Getting configs")
    r = requests.get(f"{resotocore_uri}/configs", headers=headers)
    if r.status_code == 200:
        return r.json()
    raise RuntimeError(f"Error getting configs: {r.content.decode('utf-8')}")


def get_config(config_id: str, resotocore_uri: str = None, psk: str = None) -> Dict:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Getting config {config_id}")
    r = requests.get(f"{resotocore_uri}/config/{config_id}", headers=headers)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        raise ConfigNotFoundError(f"Config {config_id} does not exist")
    raise RuntimeError(f"Error getting config {config_id}: {r.content.decode('utf-8')}")


def set_config(
    config_id: str, config: Dict, resotocore_uri: str = None, psk: str = None
) -> bool:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Storing config {config_id}")
    r = requests.put(
        f"{resotocore_uri}/config/{config_id}", json=config, headers=headers
    )
    if r.status_code == 200:
        return True
    raise RuntimeError(f"Error storing config {config_id}: {r.content.decode('utf-8')}")


def delete_config(config_id: str, resotocore_uri: str = None, psk: str = None) -> bool:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Deleting config {config_id}")
    r = requests.delete(f"{resotocore_uri}/config/{config_id}", headers=headers)
    if r.status_code == 204:
        return True
    raise RuntimeError(
        f"Error deleting config {config_id}: {r.content.decode('utf-8')}"
    )
