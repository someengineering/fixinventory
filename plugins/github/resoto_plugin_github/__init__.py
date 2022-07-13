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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.github = None

        if Config.github.access_token:
            self.github = Github(Config.github.access_token)

    def collect(self) -> None:
        if self.github is None:
            log.error("GitHub collector called but no --github-access-token provided")
            return

        log.debug("plugin: collecting GitHub resources")

        account = GithubAccount(id="GitHub")
        region = GithubRegion(id="Global")
        self.graph.add_resource(self.graph.root, account)
        self.graph.add_resource(account, region)

        for repo in Config.github.repos:
            r = GithubRepo.new(self.github.get_repo(repo))
            self.graph.add_resource(region, r)

        for org in Config.github.organizations:
            o = GithubOrg.new(self.github.get_organization(org))
            self.graph.add_resource(region, o)

        for user in Config.github.users:
            u = GithubUser.new(self.github.get_user(user))
            self.graph.add_resource(region, u)

    @staticmethod
    def add_config(config: Config) -> None:
        config.add_config(GithubConfig)
