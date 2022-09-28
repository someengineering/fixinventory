from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import random
from typing import List


@dataclass(frozen=True)
class SearchOfTheDay:

    description: str
    search: str
    difficulty: int


class SuggestionPolicy(Enum):
    RANDOM = 1
    RANDOM_NON_REPEATING = 2


class SuggestionStrategy(ABC):
    @abstractmethod
    def suggest(self) -> SearchOfTheDay:
        pass


class RandomSuggestionStrategy(SuggestionStrategy):
    def suggest(self) -> SearchOfTheDay:
        return random.sample(searches, 1)[0]


class RandomNonRepeatingSuggestionStrategy(SuggestionStrategy):
    def __init__(self):
        self._searches = list(searches)

    def suggest(self) -> SearchOfTheDay:
        if not self._searches:
            self._searches = list(searches)
        return self._searches.pop(random.randrange(len(self._searches)))


def get_suggestion_strategy(policy: SuggestionPolicy) -> SuggestionStrategy:
    if policy == SuggestionPolicy.RANDOM:
        return RandomSuggestionStrategy()
    elif policy == SuggestionPolicy.RANDOM_NON_REPEATING:
        return RandomNonRepeatingSuggestionStrategy()
    else:
        raise NotImplementedError


searches: List[SearchOfTheDay] = sorted(
    [
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
            description="Count your instances by kind",
            search="search is(aws_ec2_instance) | count kind",
            difficulty=1,
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
    ],
    key=lambda s: s.difficulty,
)
