import resotolib.logger
import resotolib.proc
from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from .resources import GithubAccount, GithubRegion, GithubOrg, GithubUser, GithubRepo
from .config import GithubConfig
from github import Github

log = resotolib.logger.getLogger("resoto." + __name__)


class GithubCollectorPlugin(BaseCollectorPlugin):
    cloud = "github"

    def collect(self) -> None:
        if Config.github.access_token is None:
            log.error("GitHub collector called but no access token provided")
            return

        github = Github(Config.github.access_token)

        log.debug("plugin: collecting GitHub resources")

        account = GithubAccount(id="GitHub")
        region = GithubRegion(id="Global")
        self.graph.add_resource(self.graph.root, account)
        self.graph.add_resource(account, region)

        for repo in Config.github.repos:
            if not "/" in repo:
                log.error(f"Invalid repo name: {repo}")
                continue
            log.debug(f"Adding repo: {repo}")
            org, repo = repo.split("/", 1)
            o = self.graph.search_first_all({"kind": "github_org", "id": org})
            if o is None:
                o = GithubOrg.new(github.get_organization(org))
                self.graph.add_resource(region, o)
            r = GithubRepo.new(github.get_repo(f"{org}/{repo}"))
            self.graph.add_resource(o, r)

        for org in Config.github.organizations:
            o = self.graph.search_first_all({"kind": "github_org", "id": org})
            if o is None:
                o = GithubOrg.new(github.get_organization(org))
                self.graph.add_resource(region, o)

        for user in Config.github.users:
            u = GithubUser.new(github.get_user(user))
            self.graph.add_resource(region, u)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(GithubConfig)
