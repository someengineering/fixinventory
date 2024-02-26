from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import random
from typing import List, FrozenSet, Deque, Tuple
from datetime import datetime
from collections import deque


@dataclass(frozen=True)
class TipOfTheDay:
    description: str
    command_line: str
    difficulty: int


class SuggestionPolicy(Enum):
    RANDOM = 1
    NON_REPEATING = 2
    DAILY = 3


class SuggestionStrategy(ABC):
    def __init__(self, cloud_providers: FrozenSet[str]):
        self._cloud_providers = cloud_providers
        tip_builder = list(generic_tips)
        if "aws" in self._cloud_providers:
            tip_builder.extend(aws_tips)
        if "digitalocean" in self._cloud_providers:
            tip_builder.extend(digitalocean_tips)
        if "k8s" in self._cloud_providers:
            tip_builder.extend(k8s_tips)
        if "gcp" in self._cloud_providers:
            tip_builder.extend(gcp_tips)
        tip_builder = sorted(tip_builder, key=lambda x: x.difficulty)
        self._tips: Tuple[TipOfTheDay, ...] = tuple(tip_builder)

    @abstractmethod
    def suggest(self) -> TipOfTheDay:
        pass


class RandomSuggestionStrategy(SuggestionStrategy):
    """
    Makes a random suggestion from the list of tips.
    """

    def suggest(self) -> TipOfTheDay:
        return random.sample(self._tips, 1)[0]


class NonRepeatingSuggestionStrategy(SuggestionStrategy):
    """
    Makes a random suggestion from the list of tips, but does not repeat
    a suggestion until all tips have been suggested.

    Keeps track of the state based on the session id.
    """

    def __init__(self, cloud_providers: FrozenSet[str]):
        super().__init__(cloud_providers)
        self._next_tips: Deque[TipOfTheDay] = deque()

    def suggest(self) -> TipOfTheDay:
        if not self._next_tips:
            self._next_tips.extend(self._tips)
        tip = self._next_tips.popleft()
        return tip


class DailyStrategy(SuggestionStrategy):
    """
    Makes a suggestion based on the day of the year. The tip is determined
    by the day of the year modulo the number of tips.
    """

    def suggest(self) -> TipOfTheDay:
        return self._tips[datetime.now().timetuple().tm_yday % len(self._tips)]


def get_suggestion_strategy(policy: SuggestionPolicy, configured_clouds: FrozenSet[str]) -> SuggestionStrategy:
    if policy == SuggestionPolicy.RANDOM:
        return RandomSuggestionStrategy(configured_clouds)
    elif policy == SuggestionPolicy.NON_REPEATING:
        return NonRepeatingSuggestionStrategy(configured_clouds)
    elif policy == SuggestionPolicy.DAILY:
        return DailyStrategy(configured_clouds)
    else:
        raise NotImplementedError


generic_tips = [
    TipOfTheDay(
        description='Find anything that contains "10.0.0.199"',
        command_line='search "10.0.0.199"',
        difficulty=1,
    ),
    TipOfTheDay(
        description="Count your instances by kind",
        command_line="search is(instance) | count kind",
        difficulty=1,
    ),
    TipOfTheDay(
        description="Format the result of your search as a json and write it to a file",
        command_line="search is(instance) | format --json | write instances.json",
        difficulty=2,
    ),
    TipOfTheDay(
        description="Find first 10 volumes, get their id and size, and display them as a markdown table",
        command_line="search is(volume) limit 10 | list id, volume_size --markdown",
        difficulty=4,
    ),
]

aws_tips: List[TipOfTheDay] = [
    TipOfTheDay(
        description="AWS EBS Volumes older than 90 days that had no I/O in the past 30 days",
        command_line="search is(aws_ec2_volume) and age > 90d and last_access > 30d",
        difficulty=2,
    ),
    TipOfTheDay(
        description="AWS EC2 instances that are missing the 'owner' tag",
        command_line="search is(aws_ec2_instance) and not has_key(tags, owner)",
        difficulty=3,
    ),
    TipOfTheDay(
        description="AWS EC2 instances that are missing the 'owner' tag",
        command_line="search is(aws_ec2_instance) and tags.owner == null",
        difficulty=3,
    ),
    TipOfTheDay(
        description='AWS network interfaces that contain "10.0.0.199" in any field',
        command_line='search is(aws_ec2_network_interface) and "10.0.0.199"',
        difficulty=2,
    ),
    TipOfTheDay(
        description="Find AWS EC2 instances and merge the instance type information into the instance data",
        command_line="search is(aws_ec2_instance) {instance_type: <-- is(aws_ec2_instance_type)}",
        difficulty=5,
    ),
    TipOfTheDay(
        description="See the detailed information about a random AWS instance",
        command_line="search is(aws_ec2_instance) | tail 1 | dump",
        difficulty=1,
    ),
    TipOfTheDay(
        description="ALBs that have no target group",
        command_line="search is(aws_alb) with(empty, --> is(aws_alb_target_group)",
        difficulty=4,
    ),
    TipOfTheDay(
        description="ELBs without EC2 instances behind them",
        command_line="search is(aws_elb) with(empty, --> is(aws_ec2_instance))",
        difficulty=4,
    ),
    TipOfTheDay(
        description="Find all expired IAM server certificates",
        command_line="search is(aws_iam_server_certificate) and expires < '@now@'",
        difficulty=3,
    ),
    TipOfTheDay(
        description="Find AWS ALB target groups of instance type that have no instances",
        command_line="search is(aws_alb_target_group) and "
        "target_type == instance with(empty, --> is(aws_ec2_instance))",
        difficulty=5,
    ),
]

gcp_tips: List[TipOfTheDay] = [
    TipOfTheDay(
        description="See the detailed information about a random GCP instance",
        command_line="search is(gcp_instance) | tail 1 | dump",
        difficulty=2,
    ),
]

digitalocean_tips: List[TipOfTheDay] = [
    TipOfTheDay(
        description="Digitalocean Volumes older than 90 days that had no I/O in the past 30 days",
        command_line="search is(digitalocean_volume) and age > 90d and last_access > 30d",
        difficulty=2,
    ),
    TipOfTheDay(
        description="DigitalOcean droplets that are missing the 'owner' tag",
        command_line="search is(digitalocean_droplet) and not has_key(tags, owner)",
        difficulty=3,
    ),
    TipOfTheDay(
        description="DigitalOcean droplets that are missing the 'owner' tag",
        command_line="search is(digitalocean_droplet) and tags.owner == null",
        difficulty=3,
    ),
    TipOfTheDay(
        description='DigitalOcean VPCs that contain "10.0.0.199" in any field',
        command_line='search is(digitalocean_vpc) and "10.0.0.199"',
        difficulty=2,
    ),
    TipOfTheDay(
        description="See the detailed information about a random DigitalOcean droplet",
        command_line="search is(digitalocean_droplet) | tail 1 | dump",
        difficulty=2,
    ),
    TipOfTheDay(
        description="Find all expired DigitalOceans certificates",
        command_line="search is(digitalocean_certificate) and expires < '@now@'",
        difficulty=3,
    ),
]

k8s_tips: List[TipOfTheDay] = [
    TipOfTheDay(
        description="Kubernetes pods that are missing the 'owner' tag",
        command_line="search is(k8s_pod) and not has_key(labels, owner)",
        difficulty=3,
    ),
]
