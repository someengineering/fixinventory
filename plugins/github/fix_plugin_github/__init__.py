import fixlib.logger
import fixlib.proc
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.config import Config
from fixlib.durations import parse_duration
from fixlib.utils import make_valid_timestamp
from datetime import datetime, timezone
from .resources import GithubAccount, GithubRegion, GithubOrg, GithubUser, GithubRepo, GithubPullRequest
from .config import GithubConfig
from github import Github
from github.GithubException import UnknownObjectException
from github.PullRequest import PullRequest


log = fixlib.logger.getLogger("fix." + __name__)


class GithubCollectorPlugin(BaseCollectorPlugin):
    cloud = "github"

    def collect(self) -> None:
        if Config.github.access_token is None:
            log.error("GitHub collector called but no access token provided")
            return

        github = Github(Config.github.access_token)
        pull_request_state = Config.github.pull_request_state.value
        pull_request_sort = Config.github.pull_request_sort.value
        pull_request_direction = Config.github.pull_request_direction.value
        pull_request_limit = Config.github.pull_request_limit
        pull_request_age = Config.github.pull_request_age
        if pull_request_age is not None:
            pull_request_age = parse_duration(pull_request_age)

        log.debug("plugin: collecting GitHub resources")

        account = GithubAccount(id="GitHub")
        region = GithubRegion(id="Global")
        self.graph.add_resource(self.graph.root, account)
        self.graph.add_resource(account, region)

        for org in Config.github.organizations:
            o = GithubOrg.new(github.get_organization(org))
            log.debug(f"Adding {o.kdname}")
            self.graph.add_resource(region, o)

        for user in Config.github.users:
            u = GithubUser.new(github.get_user(user))
            log.debug(f"Adding {u.kdname}")
            self.graph.add_resource(region, u)

        for repo_fullname in Config.github.repos:
            if "/" not in repo_fullname:
                log.error(f"Invalid repo name: {repo_fullname}")
                continue
            log.debug(f"Adding repo: {repo_fullname}")
            org_or_user = repo_fullname.split("/")[0]
            src = self.graph.search_first_all({"kind": "github_org", "id": org_or_user})
            if src is None:
                try:
                    src = GithubOrg.new(github.get_organization(org_or_user))
                    log.debug(f"Adding {src.kdname}")
                    self.graph.add_resource(region, src)
                except UnknownObjectException:
                    src = self.graph.search_first_all({"kind": "github_user", "id": org_or_user})
                    if src is None:
                        try:
                            src = GithubUser.new(github.get_user(org_or_user))
                            log.debug(f"Adding {src.kdname}")
                            self.graph.add_resource(region, src)
                        except UnknownObjectException:
                            log.error(f"Could not find an org or user for repo: {repo_fullname} - skipping")
                            continue

            repo = github.get_repo(repo_fullname)
            r = GithubRepo.new(repo)
            log.debug(f"Adding {r.kdname}")
            self.graph.add_resource(src, r)

            def too_old(pull_request: PullRequest) -> bool:
                if pull_request_age is not None:
                    if pull_request_sort == "updated":
                        pr_timestamp = make_valid_timestamp(pull_request.updated_at)
                    else:
                        pr_timestamp = make_valid_timestamp(pull_request.created_at)
                    pr_age = datetime.utcnow().replace(tzinfo=timezone.utc) - pr_timestamp
                    if pr_age > pull_request_age:
                        log.debug(f"Reached pull request age limit of {pull_request_age}")
                        return True
                return False

            def too_many(pr_i: int) -> bool:
                if pull_request_limit is not None and pr_i == pull_request_limit:
                    log.debug(f"Reached pull request limit of {pull_request_limit}")
                    return True
                return False

            log.debug(
                f"Fetching pull requests for {r.kdname}:"
                f" state={pull_request_state}, sort={pull_request_sort}, direction={pull_request_direction}"
            )
            for pr_i, pull_request in enumerate(
                repo.get_pulls(state=pull_request_state, sort=pull_request_sort, direction=pull_request_direction)
            ):
                if too_many(pr_i) or too_old(pull_request):
                    break

                pr = GithubPullRequest.new(pull_request)
                log.debug(f"Adding {pr.kdname}")
                self.graph.add_resource(r, pr)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(GithubConfig)
