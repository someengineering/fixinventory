import requests
import json
from cklib.args import ArgumentParser
from cklib.jwt import encode_jwt_to_headers
from typing import Iterator


def query(query_str: str, query_uri: str) -> Iterator:
    headers = {"Accept": "application/x-ndjson"}
    if ArgumentParser.args.psk:
        encode_jwt_to_headers(headers, {}, ArgumentParser.args.psk)

    r = requests.post(
        query_uri,
        data=query_str,
        headers=headers,
        stream=True,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Failed to query graph: {r.content}")

    for line in r.iter_lines():
        if not line:
            continue

        data = json.loads(line.decode("utf-8"))
        yield data


def get_metrics_from_result(result: dict):
    result_metrics = dict(result)
    del result_metrics["group"]
    return result_metrics


def get_labels_from_result(result: dict):
    labels = tuple(result.get("group", {}).keys())
    return labels


def get_label_values_from_result(result: dict, labels: tuple):
    label_values = []
    for label in labels:
        label_value = result.get("group", {}).get(label)
        if label_value is None:
            label_value = ""
        label_values.append(str(label_value))
    return tuple(label_values)
