import tempfile
from pathlib import Path
from typing import List

from resoto_plugin_aws.resource.base import AwsRegion
from resoto_plugin_aws.utils import arn_partition, get_aws_profiles_from_file


def test_arn_partition() -> None:
    us_east_1 = AwsRegion(id="us-east-1")
    cn_north_1 = AwsRegion(id="cn-north-1")
    us_gov_east_1 = AwsRegion(id="us-gov-east-1")
    assert arn_partition(us_east_1) == "aws"
    assert arn_partition(cn_north_1) == "aws-cn"
    assert arn_partition(us_gov_east_1) == "aws-us-gov"


def test_credentials_reader() -> None:
    def with_file(content: str, expected_profiles: List[str]) -> None:
        with tempfile.NamedTemporaryFile(mode="w") as f:
            f.write(content)
            f.flush()
            assert set(get_aws_profiles_from_file(Path(f.name))) == set(expected_profiles)

    with_file("", [])
    ak = "aws_access_key_id=123"
    with_file("[default]\n", [])
    with_file(f"[default]\n{ak}\n", ["default"])
    with_file(f"[1]\n{ak}\n[2]\n{ak}\n", ["1", "2"])
    with_file(f"[1]\n{ak}\n[2]\n\n[3]\n{ak}\n", ["1", "3"])
