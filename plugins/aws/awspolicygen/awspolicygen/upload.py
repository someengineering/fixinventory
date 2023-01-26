import os
import re
import sys
import glob
import boto3
import requests
import time
import mimetypes
import magic
import json
import tempfile
from botocore.client import BaseClient
from functools import lru_cache
from argparse import Namespace
from typing import Optional
from . import log


mimetypes.init()
mime = magic.Magic(mime=True)


def upload_policies(policies: list, args: Namespace) -> None:
    """Upload the Resoto AWS policies to the CDN."""
    log.info("Uploading Resoto AWS policies to the CDN")
    client = s3_client(args.spaces_region, args.spaces_key, args.spaces_secret)

    # github_ref format:
    # refs/pull/14/merge
    # refs/tags/v0.0.1
    # refs/heads/master
    destinations = ["edge"]
    if not None in (args.github_ref, args.github_ref_type, args.github_event_name):
        log.debug(f"GitHub ref: {args.github_ref}, type: {args.github_ref_type}, event: {args.github_event_name}")

        if str(args.github_event_name) == "pull_request":
            log.info("Not uploading for PR")
            sys.exit(0)

        m = re.search(r"^refs/tags/(.+)$", str(args.github_ref))
        if m and args.github_ref_type == "tag":
            destination = m.group(1)
            destinations = ["latest", destination]

    purge_keys = []
    with tempfile.TemporaryDirectory() as tmpdirname:
        log.debug(f"Created temporary directory: {tmpdirname}")
        for policy in policies:
            filename = f"{tmpdirname}/{policy['PolicyName']}.json"
            with open(filename, "w") as f:
                json.dump(policy["PolicyDocument"], f, indent=4)

        for destination in destinations:
            for filename in glob.iglob(tmpdirname + "**/**", recursive=True):
                if not os.path.isfile(filename):
                    continue
                basename = filename[len(tmpdirname) + 1 :]
                key_name = f"{args.spaces_path}{destination}/{basename}"
                ctype = content_type(filename, ttl_hash=ttl_hash())
                log.debug(f"Uploading {filename} to {key_name}, type: {ctype}")
                upload_file(client, filename=filename, key=key_name, spaces_name=args.spaces_name, ctype=ctype)
                purge_keys.append(key_name)

    try:
        purge_cdn(purge_keys, args.api_token, args.spaces_name, args.spaces_region)
    except RuntimeError as e:
        log.error(e)


def s3_client(region: str, key: str, secret: str) -> BaseClient:
    session = boto3.session.Session()
    return session.client(
        "s3",
        region_name=region,
        endpoint_url=f"https://{region}.digitaloceanspaces.com",
        aws_access_key_id=key,
        aws_secret_access_key=secret,
    )


def upload_file(
    client: BaseClient,
    filename: str,
    key: str,
    spaces_name: str,
    acl: str = "public-read",
    ctype: str = "binary/octet-stream",
) -> None:
    with open(filename, "rb") as f:
        client.upload_fileobj(f, spaces_name, key, ExtraArgs={"ACL": acl, "ContentType": ctype})


@lru_cache
def content_type(filename: str, ttl_hash: Optional[int] = None) -> str:
    ctype = mimetypes.guess_type(filename)[0]
    if ctype is None:
        ctype = mime.from_file(filename)
    if ctype in ("inode/x-empty"):
        ctype = "binary/octet-stream"
    return ctype


def purge_cdn(files: list, api_token: str, spaces_name: str, region: str) -> None:
    """Purge the CDN cache for the given files."""
    endpoints = cdn_endpoints(api_token, ttl_hash=ttl_hash())
    log.info(f"Purging CDN cache for {len(files)} files")
    endpoint_key = f"{spaces_name}.{region}.digitaloceanspaces.com"
    if endpoint_key not in endpoints:
        raise RuntimeError(f"No CDN endpoint for {endpoint_key}")
    endpoint_id = endpoints[endpoint_key]
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    data = {"files": files}
    response = requests.delete(
        f"https://api.digitalocean.com/v2/cdn/endpoints/{endpoint_id}/cache", json=data, headers=headers
    )
    if response.status_code != 204:
        raise RuntimeError(f"failed to purge CDN cache: {response.status_code} {response.text}")


@lru_cache(maxsize=1)
def cdn_endpoints(api_token: str, ttl_hash: Optional[int] = None) -> dict:
    """Get the CDN endpoint from the DigitalOcean API."""
    log.debug("Getting all CDN endpoints from the DigitalOcean API")
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    endpoints = {}
    next_uri = "https://api.digitalocean.com/v2/cdn/endpoints?per_page=200"
    while True:
        response = requests.get(next_uri, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"failed to get CDN endpoint: {response.text}")
        data = response.json()
        if not "endpoints" in data:
            raise ValueError(f"no CDN endpoint in response: {response.text}")
        for endpoint in data["endpoints"]:
            endpoints[endpoint["origin"]] = endpoint["id"]
        if data.get("links", {}).get("pages", {}).get("next", None) is None:
            break
        next_uri = data["links"]["pages"]["next"]
    return endpoints


def ttl_hash(ttl: int = 3600) -> int:
    return round(time.time() / ttl)
