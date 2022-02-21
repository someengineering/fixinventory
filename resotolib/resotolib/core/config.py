import requests
from typing import Dict, Tuple
from resotolib.args import ArgumentParser
from resotolib.jwt import encode_jwt_to_headers
from resotolib.logging import log


def default_args(
    resotocore_uri: str = None, psk: str = None, headers=None
) -> Tuple[str, str, Dict[str, str]]:
    if resotocore_uri is None:
        resotocore_uri = getattr(ArgumentParser.args, "resotocore_uri", None)
    if psk is None:
        psk = getattr(ArgumentParser.args, "psk", None)
    if headers is None:
        headers = {}
    if psk is not None:
        encode_jwt_to_headers(headers, {}, psk)
    return resotocore_uri, psk, headers


def get_config(config_id: str, resotocore_uri: str = None, psk: str = None) -> Dict:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Getting config {config_id}")
    r = requests.get(f"{resotocore_uri}/config/{config_id}", headers=headers)
    if r.status_code == 200:
        return r.json()
    log.error(f"Error {r.status_code}: {r.content.decode('utf-8')}")
    return None


def set_config(
    config_id: str, config: Dict, resotocore_uri: str = None, psk: str = None
) -> bool:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Setting config {config_id}")
    r = requests.put(
        f"{resotocore_uri}/config/{config_id}", json=config, headers=headers
    )
    if r.status_code == 200:
        return True
    log.error(f"Error {r.status_code}: {r.content.decode('utf-8')}")
    return False


def delete_config(config_id: str, resotocore_uri: str = None, psk: str = None) -> bool:
    resotocore_uri, psk, headers = default_args(resotocore_uri, psk)

    log.debug(f"Deleting config {config_id}")
    r = requests.delete(f"{resotocore_uri}/config/{config_id}", headers=headers)
    if r.status_code == 204:
        return True
    log.error(f"Error {r.status_code}: {r.content.decode('utf-8')}")
    return False
