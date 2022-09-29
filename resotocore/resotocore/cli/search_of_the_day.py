from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import random
from typing import List, FrozenSet, Deque, Tuple
from datetime import datetime
from collections import deque


@dataclass(frozen=True)
class SearchOfTheDay:
    description: str
    search: str
    difficulty: int


class SuggestionPolicy(Enum):
    RANDOM = 1
    NON_REPEATING = 2
    DAILY = 3


class SuggestionStrategy(ABC):
    def __init__(self, cloud_providers: FrozenSet[str]):
        self._cloud_providers = cloud_providers
        search_builder = list(generic_searches)
        if "aws" in self._cloud_providers:
            search_builder.extend(aws_searches)
        if "digitalocean" in self._cloud_providers:
            search_builder.extend(digitalocean_searches)
        search_builder = sorted(search_builder, key=lambda x: x.difficulty)
        self._searches: Tuple[SearchOfTheDay, ...] = tuple(search_builder)

    @abstractmethod
    def suggest(self) -> SearchOfTheDay:
        pass


class RandomSuggestionStrategy(SuggestionStrategy):
    """
    Makes a random suggestion from the list of searches.
    """

    def suggest(self) -> SearchOfTheDay:
        return random.sample(self._searches, 1)[0]


class NonRepeatingSuggestionStrategy(SuggestionStrategy):
    """
    Makes a random suggestion from the list of searches, but does not repeat
    a suggestion until all searches have been suggested.

    Keeps track of the state based on the session id.
    """

    def __init__(self, cloud_providers: FrozenSet[str]):
        super().__init__(cloud_providers)
        self._next_searches: Deque[SearchOfTheDay] = deque()

    def suggest(self) -> SearchOfTheDay:
        if not self._next_searches:
            self._next_searches.extend(self._searches)
        search = self._next_searches.popleft()
        return search


class DailySearchStrategy(SuggestionStrategy):
    """
    Makes a suggestion based on the day of the year. The search is determined
    by the day of the year modulo the number of searches.
    """

    def suggest(self) -> SearchOfTheDay:
        return self._searches[datetime.now().timetuple().tm_yday % len(self._searches)]


def get_suggestion_strategy(policy: SuggestionPolicy, configured_clouds: FrozenSet[str]) -> SuggestionStrategy:
    if policy == SuggestionPolicy.RANDOM:
        return RandomSuggestionStrategy(configured_clouds)
    elif policy == SuggestionPolicy.NON_REPEATING:
        return NonRepeatingSuggestionStrategy(configured_clouds)
    elif policy == SuggestionPolicy.DAILY:
        return DailySearchStrategy(configured_clouds)
    else:
        raise NotImplementedError


generic_searches = [
    SearchOfTheDay(
        description='Anything that contains "10.0.0.199"',
        search='search "10.0.0.199"',
        difficulty=1,
    ),
    SearchOfTheDay(
        description="Count your instances by kind",
        search="search is(instance) | count kind",
        difficulty=1,
    ),
]

aws_searches: List[SearchOfTheDay] = [
    SearchOfTheDay(
        description="AWS EBS Volumes older than 90 days that had no I/O in the past 30 days",
        search="search is(aws_ec2_volume) and age > 90d and last_access > 30d",
        difficulty=2,
    ),
    SearchOfTheDay(
        description="AWS EC2 instances that are missing the 'owner' tag",
        search="search is(aws_ec2_instance) and not has_key(tags, owner)",
        difficulty=3,
    ),
    SearchOfTheDay(
        description="AWS EC2 instances that are missing the 'owner' tag",
        search="search is(aws_ec2_instance) and tags.owner == null",
        difficulty=3,
    ),
    SearchOfTheDay(
        description='AWS network interfaces that contain "10.0.0.199" in any field',
        search='search is(aws_ec2_network_interface) and "10.0.0.199"',
        difficulty=2,
    ),
    SearchOfTheDay(
        description='Anything that contains "10.0.0.199"',
        search='search "10.0.0.199"',
        difficulty=1,
    ),
    SearchOfTheDay(
        description="Find AWS EC2 instances and merge the instance type information into the instance data",
        search="search is(aws_ec2_instance) {instance_type: <-- is(aws_ec2_instance_type)}",
        difficulty=5,
    ),
    SearchOfTheDay(
        description="See the detailed information about a random AWS instance",
        search="search is(aws_ec2_instance) | tail 1 | dump",
        difficulty=1,
    ),
    SearchOfTheDay(
        description="ALBs that have no target group",
        search="search is(aws_alb) with(empty, --> is(aws_alb_target_group)",
        difficulty=4,
    ),
    SearchOfTheDay(
        description="ELBs without EC2 instances behind them",
        search="search is(aws_elb) with(empty, --> is(aws_ec2_instance))",
        difficulty=4,
    ),
    SearchOfTheDay(
        description="Find all expired IAM server certificates",
        search="search is(aws_iam_server_certificate) and expires < '@now@'",
        difficulty=3,
    ),
    SearchOfTheDay(
        description="Find AWS ALB target groups of instance type that have no instances",
        search="search is(aws_alb_target_group) and target_type == instance with(empty, --> is(aws_ec2_instance))",
        difficulty=5,
    ),
]

digitalocean_searches: List[SearchOfTheDay] = [
    SearchOfTheDay(
        description="Digitalocean Volumes older than 90 days that had no I/O in the past 30 days",
        search="search is(digitalocean_volume) and age > 90d and last_access > 30d",
        difficulty=2,
    ),
    SearchOfTheDay(
        description="DigitalOcean droplets that are missing the 'owner' tag",
        search="search is(digitalocean_droplet) and not has_key(tags, owner)",
        difficulty=3,
    ),
    SearchOfTheDay(
        description="DigitalOcean droplets that are missing the 'owner' tag",
        search="search is(digitalocean_droplet) and tags.owner == null",
        difficulty=3,
    ),
    SearchOfTheDay(
        description='DigitalOcean VPCs that contain "10.0.0.199" in any field',
        search='search is(digitalocean_vpc) and "10.0.0.199"',
        difficulty=2,
    ),
    SearchOfTheDay(
        description="See the detailed information about a random DigitalOcean droplet",
        search="search is(digitalocean_droplet) | tail 1 | dump",
        difficulty=1,
    ),
    SearchOfTheDay(
        description="Find all expired DigitalOceans certificates",
        search="search is(digitalocean_certificate) and expires < '@now@'",
        difficulty=3,
    ),
]
