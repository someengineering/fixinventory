from cloudkeeper.baseresources import BaseResource
import cloudkeeper.logging
import multiprocessing
import cloudkeeper.signal
from concurrent import futures
from cloudkeeper.baseplugin import BaseCollectorPlugin
from cloudkeeper.args import ArgumentParser
from .resources import GithubAccount, GithubRegion, GithubOrg, GithubUser, GithubRepo
from typing import Dict
from github import Github

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class GithubCollectorPlugin(BaseCollectorPlugin):
    cloud = "github"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.github = None

        if ArgumentParser.args.github_access_token:
            self.github = Github(ArgumentParser.args.github_access_token)

    def collect(self) -> None:
        if self.github is None:
            log.error("GitHub collector called but no --github-access-token provided")
            return

        log.debug("plugin: collecting GitHub resources")

        account = GithubAccount("GitHub")
        region = GithubRegion("Global")
        self.graph.add_resource(self.graph.root, account)
        self.graph.add_resource(account, region)

        for repo in ArgumentParser.args.github_repos:
            r = GithubRepo.new(self.github.get_repo(repo))
            self.graph.add_resource(region, r)

        for org in ArgumentParser.args.github_orgs:
            o = GithubOrg.new(self.github.get_organization(org))
            self.graph.add_resource(region, o)

        for user in ArgumentParser.args.github_users:
            u = GithubUser.new(self.github.get_user(user))
            self.graph.add_resource(region, u)

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument(
            "--github-access-token",
            help="GitHub access token",
            dest="github_access_token",
            type=str,
            default=None,
        )
        arg_parser.add_argument(
            "--github-org",
            help="GitHub Organizations",
            dest="github_orgs",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--github-repo",
            help="GitHub Repositories",
            dest="github_repos",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--github-user",
            help="GitHub Users",
            dest="github_users",
            type=str,
            default=[],
            nargs="+",
        )
        arg_parser.add_argument(
            "--github-pool-size",
            help="GitHub Thread Pool Size (default: 5)",
            dest="github_pool_size",
            default=5,
            type=int,
        )
        arg_parser.add_argument(
            "--github-fork",
            help="GitHub use forked process instead of threads (default: False)",
            dest="github_fork",
            action="store_true",
        )
