import boto3
import boto3.session
import uuid
from typing import Iterable
from cloudkeeper.args import ArgumentParser
from cloudkeeper.baseresources import BaseResource
from cloudkeeper.graph import Graph


def aws_session(aws_account=None, aws_role=None):
    if ArgumentParser.args.aws_role_override:
        aws_role = ArgumentParser.args.aws_role
    if aws_role and aws_account:
        role_arn = f"arn:aws:iam::{aws_account}:role/{aws_role}"
        session = boto3.session.Session(
            aws_access_key_id=ArgumentParser.args.aws_access_key_id,
            aws_secret_access_key=ArgumentParser.args.aws_secret_access_key,
            region_name="us-east-1",
        )
        sts = session.client("sts")
        token = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"{aws_account}-{str(uuid.uuid4())}")
        credentials = token["Credentials"]
        return boto3.session.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    else:
        return boto3.session.Session(
            aws_access_key_id=ArgumentParser.args.aws_access_key_id,
            aws_secret_access_key=ArgumentParser.args.aws_secret_access_key,
        )


def aws_client(resource: BaseResource, service: str, graph: Graph = None):
    return aws_session(resource.account(graph).id, resource.account(graph).role).client(
        service, region_name=resource.region(graph).id
    )


def aws_resource(resource: BaseResource, service: str, graph: Graph = None):
    return aws_session(resource.account(graph).id, resource.account(graph).role).resource(
        service, region_name=resource.region(graph).id
    )


def paginate(method: callable, **kwargs) -> Iterable:
    """Get a paginator for a boto3 list/describe method

    Example Usage:
    session = aws_session(self.account.id, self.account.role)
    client = session.client('autoscaling', region_name=region.id)
    for autoscaling_group in paginate(client.describe_auto_scaling_groups):
        print(autoscaling_group)
    """
    client = method.__self__
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result
