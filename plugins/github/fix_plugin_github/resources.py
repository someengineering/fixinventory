from datetime import datetime
from attrs import define
from typing import Optional, ClassVar, List, Dict, Any, Union
from fixlib.graph import Graph
from fixlib.logger import log
from fixlib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    BaseUser,
)
from fixlib.utils import make_valid_timestamp
from github.Repository import Repository
from github.Organization import Organization
from github.NamedUser import NamedUser
from github.Clones import Clones
from github.View import View
from github.Referrer import Referrer
from github.Path import Path
from github.GithubException import GithubException
from github.PullRequest import PullRequest


@define(eq=False, slots=False)
class GithubAccount(BaseAccount):
    kind: ClassVar[str] = "github_account"
    kind_display: ClassVar[str] = "Github Account"
    kind_description: ClassVar[str] = "A Github Account."

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class GithubRegion(BaseRegion):
    kind: ClassVar[str] = "github_region"
    kind_display: ClassVar[str] = "Github Region"
    kind_description: ClassVar[str] = "A Github Region."

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class GithubResource:
    kind: ClassVar[str] = "github_resource"
    kind_display: ClassVar[str] = "Github Resource"
    kind_description: ClassVar[str] = "A Github Resource."

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class GithubOrg(GithubResource, BaseResource):
    kind: ClassVar[str] = "github_org"
    kind_display: ClassVar[str] = "Github Organization"
    kind_description: ClassVar[str] = "A Github Organization."

    avatar_url: Optional[str] = None
    billing_email: Optional[str] = None
    blog: Optional[str] = None
    collaborators: Optional[int] = None
    company: Optional[str] = None
    created_at: Optional[datetime] = None
    default_repository_permission: Optional[str] = None
    description: Optional[str] = None
    disk_usage: Optional[int] = None
    email: Optional[str] = None
    events_url: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    gravatar_id: Optional[str] = None
    has_organization_projects: Optional[bool] = None
    has_repository_projects: Optional[bool] = None
    hooks_url: Optional[str] = None
    html_url: Optional[str] = None
    org_id: Optional[int] = None
    issues_url: Optional[str] = None
    org_location: Optional[str] = None
    login: Optional[str] = None
    members_can_create_repositories: Optional[bool] = None
    members_url: Optional[str] = None
    owned_private_repos: Optional[int] = None
    private_gists: Optional[int] = None
    public_gists: Optional[int] = None
    public_members_url: Optional[str] = None
    public_repos: Optional[int] = None
    repos_url: Optional[str] = None
    total_private_repos: Optional[int] = None
    two_factor_requirement_enabled: Optional[bool] = None
    org_type: Optional[str] = None
    updated_at: Optional[datetime] = None
    url: Optional[str] = None

    @staticmethod
    def new(org: Organization) -> BaseResource:
        return GithubOrg(
            id=str(org.login),
            name=org.name,
            avatar_url=org.avatar_url,
            billing_email=org.billing_email,
            blog=org.blog,
            collaborators=org.collaborators,
            company=org.company,
            created_at=make_valid_timestamp(org.created_at),
            ctime=make_valid_timestamp(org.created_at),
            default_repository_permission=org.default_repository_permission,
            description=org.description,
            disk_usage=org.disk_usage,
            email=org.email,
            events_url=org.events_url,
            followers=org.followers,
            following=org.following,
            gravatar_id=org.gravatar_id,
            has_organization_projects=org.has_organization_projects,
            has_repository_projects=org.has_repository_projects,
            hooks_url=org.hooks_url,
            html_url=org.html_url,
            org_id=org.id,
            issues_url=org.issues_url,
            org_location=org.location,
            login=org.login,
            members_can_create_repositories=org.members_can_create_repositories,
            members_url=org.members_url,
            owned_private_repos=org.owned_private_repos,
            private_gists=org.private_gists,
            public_gists=org.public_gists,
            public_members_url=org.public_members_url,
            public_repos=org.public_repos,
            repos_url=org.repos_url,
            total_private_repos=org.total_private_repos,
            org_type=org.type,
            updated_at=make_valid_timestamp(org.updated_at),
            mtime=make_valid_timestamp(org.updated_at),
            url=org.url,
        )


@define(eq=False, slots=False)
class GithubUser(GithubResource, BaseUser):
    kind: ClassVar[str] = "github_user"
    kind_display: ClassVar[str] = "Github User"
    kind_description: ClassVar[str] = "A Github User."

    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    blog: Optional[str] = None
    collaborators: Optional[int] = None
    company: Optional[str] = None
    contributions: Optional[int] = None
    created_at: Optional[datetime] = None
    disk_usage: Optional[int] = None
    email: Optional[str] = None
    events_url: Optional[str] = None
    followers: Optional[int] = None
    followers_url: Optional[str] = None
    following: Optional[int] = None
    following_url: Optional[str] = None
    gists_url: Optional[str] = None
    gravatar_id: Optional[str] = None
    hireable: Optional[bool] = None
    html_url: Optional[str] = None
    user_id: Optional[int] = None
    invitation_teams_url: Optional[str] = None
    user_location: Optional[str] = None
    login: Optional[str] = None
    name: Optional[str] = None
    node_id: Optional[int] = None
    organizations_url: Optional[str] = None
    owned_private_repos: Optional[int] = None
    private_gists: Optional[int] = None
    public_gists: Optional[int] = None
    public_repos: Optional[int] = None
    received_events_url: Optional[str] = None
    repos_url: Optional[str] = None
    role: Optional[str] = None
    site_admin: Optional[bool] = None
    starred_url: Optional[str] = None
    subscriptions_url: Optional[str] = None
    suspended_at: Optional[datetime] = None
    team_count: Optional[int] = None
    total_private_repos: Optional[int] = None
    twitter_username: Optional[str] = None
    user_type: Optional[str] = None
    updated_at: Optional[datetime] = None
    url: Optional[str] = None

    @staticmethod
    def new(user: NamedUser) -> BaseResource:
        return GithubUser(
            id=str(user.login),
            avatar_url=user.avatar_url,
            bio=user.bio,
            blog=user.blog,
            collaborators=user.collaborators,
            company=user.company,
            contributions=user.contributions,
            created_at=make_valid_timestamp(user.created_at),
            ctime=make_valid_timestamp(user.created_at),
            disk_usage=user.disk_usage,
            email=user.email,
            events_url=user.events_url,
            followers=user.followers,
            followers_url=user.followers_url,
            following=user.following,
            following_url=user.following_url,
            gists_url=user.gists_url,
            gravatar_id=user.gravatar_id,
            hireable=user.hireable,
            html_url=user.html_url,
            user_id=user.id,
            invitation_teams_url=user.invitation_teams_url,
            user_location=user.location,
            login=user.login,
            name=user.name,
            node_id=user.id,
            organizations_url=user.organizations_url,
            owned_private_repos=user.owned_private_repos,
            private_gists=user.private_gists,
            public_gists=user.public_gists,
            public_repos=user.public_repos,
            received_events_url=user.received_events_url,
            repos_url=user.repos_url,
            role=user.role,
            site_admin=user.site_admin,
            starred_url=user.starred_url,
            subscriptions_url=user.subscriptions_url,
            suspended_at=make_valid_timestamp(user.suspended_at),
            team_count=user.team_count,
            total_private_repos=user.total_private_repos,
            twitter_username=user.twitter_username,
            user_type=user.type,
            updated_at=make_valid_timestamp(user.updated_at),
            mtime=make_valid_timestamp(user.updated_at),
            url=user.url,
        )


@define(eq=False, slots=False)
class GithubRepoClones:
    kind: ClassVar[str] = "github_repo_clones"
    kind_display: ClassVar[str] = "Github Repository Clones"
    kind_description: ClassVar[str] = "A Github Repository Clones."

    timestamp: Optional[datetime] = None
    count: Optional[int] = None
    uniques: Optional[int] = None

    @staticmethod
    def new(clones: Clones):
        return GithubRepoClones(
            timestamp=make_valid_timestamp(clones.timestamp), count=clones.count, uniques=clones.uniques
        )


@define(eq=False, slots=False)
class GithubRepoClonesTraffic:
    kind: ClassVar[str] = "github_repo_clones_traffic"
    kind_display: ClassVar[str] = "Github Repository Clones Traffic"
    kind_description: ClassVar[str] = "Github Repository Clones Traffic."

    count: Optional[int] = None
    uniques: Optional[int] = None
    clones: Optional[List[GithubRepoClones]] = None

    @staticmethod
    def new(clones_traffic: Optional[Dict[str, Any]]):
        if clones_traffic is None:
            return None

        return GithubRepoClonesTraffic(
            count=clones_traffic.get("count"),
            uniques=clones_traffic.get("uniques"),
            clones=[GithubRepoClones.new(clones) for clones in clones_traffic.get("clones", [])],
        )


@define(eq=False, slots=False)
class GithubRepoView:
    kind: ClassVar[str] = "github_repo_view"
    kind_display: ClassVar[str] = "Github Repository View"
    kind_description: ClassVar[str] = "The Github Repository View."

    timestamp: Optional[datetime] = None
    count: Optional[int] = None
    uniques: Optional[int] = None

    @staticmethod
    def new(view: View):
        return GithubRepoView(timestamp=make_valid_timestamp(view.timestamp), count=view.count, uniques=view.uniques)


@define(eq=False, slots=False)
class GithubRepoViewsTraffic:
    kind: ClassVar[str] = "github_repo_views_traffic"
    kind_display: ClassVar[str] = "Github Repository Views Traffic"
    kind_description: ClassVar[str] = "Github Repository Views Traffic."

    count: Optional[int] = None
    uniques: Optional[int] = None
    views: Optional[List[GithubRepoView]] = None

    @staticmethod
    def new(views_traffic: Optional[Dict[str, Any]]):
        if views_traffic is None:
            return None

        return GithubRepoViewsTraffic(
            count=views_traffic.get("count"),
            uniques=views_traffic.get("uniques"),
            views=[GithubRepoView.new(view) for view in views_traffic.get("views", [])],
        )


@define(eq=False, slots=False)
class GithubRepoTopReferrer:
    kind: ClassVar[str] = "github_repo_top_referrer"
    kind_display: ClassVar[str] = "Github Repository Top Referrer"
    kind_description: ClassVar[str] = "Github Repository Top Referrer."

    referrer: Optional[str] = None
    count: Optional[int] = None
    uniques: Optional[int] = None

    @staticmethod
    def new(referrer: Referrer):
        return GithubRepoTopReferrer(referrer=referrer.referrer, count=referrer.count, uniques=referrer.uniques)


@define(eq=False, slots=False)
class GithubRepoTopPath:
    kind: ClassVar[str] = "github_repo_top_path"
    kind_display: ClassVar[str] = "Github Repository Top Path"
    kind_description: ClassVar[str] = "Github Repository Top Path."

    title: Optional[str] = None
    path: Optional[str] = None
    count: Optional[int] = None
    uniques: Optional[int] = None

    @staticmethod
    def new(path: Path):
        return GithubRepoTopPath(title=path.title, path=path.path, count=path.count, uniques=path.uniques)


@define(eq=False, slots=False)
class GithubPullRequest(GithubResource, BaseResource):
    kind: ClassVar[str] = "github_pull_request"
    kind_display: ClassVar[str] = "Github Pull Request"
    kind_description: ClassVar[str] = "A Github Pull Request."

    additions: Optional[int] = None
    # assignee: Optional[str] = None
    # assignees: Optional[List[str]] = None
    # base: Optional[str] = None
    body: Optional[str] = None
    changed_files: Optional[int] = None
    closed_at: Optional[datetime] = None
    comments: Optional[int] = None
    comments_url: Optional[str] = None
    commits: Optional[int] = None
    commits_url: Optional[str] = None
    created_at: Optional[datetime] = None
    deletions: Optional[int] = None
    diff_url: Optional[str] = None
    draft: Optional[bool] = None
    # head: Optional[str] = None
    html_url: Optional[str] = None
    pr_id: Optional[int] = None
    issue_url: Optional[str] = None
    # labels: Optional[List[str]] = None
    merge_commit_sha: Optional[str] = None
    mergeable: Optional[bool] = None
    mergeable_state: Optional[str] = None
    merged: Optional[bool] = None
    merged_at: Optional[datetime] = None
    # merged_by: Optional[str] = None
    # milestone: Optional[str] = None
    number: Optional[int] = None
    patch_url: Optional[str] = None
    rebaseable: Optional[bool] = None
    review_comments: Optional[int] = None
    review_comments_url: Optional[str] = None
    state: Optional[str] = None
    title: Optional[str] = None
    updated_at: Optional[datetime] = None
    url: Optional[str] = None
    # user: Optional[str] = None
    maintainer_can_modify: Optional[bool] = None

    @staticmethod
    def new(pr: PullRequest):
        return GithubPullRequest(
            name=str(pr.title),
            additions=pr.additions,
            # assignee=pr.assignee,
            # assignees=pr.assignees,
            # base=pr.base,
            body=pr.body,
            changed_files=pr.changed_files,
            closed_at=make_valid_timestamp(pr.closed_at),
            comments=pr.comments,
            comments_url=pr.comments_url,
            commits=pr.commits,
            commits_url=pr.commits_url,
            created_at=make_valid_timestamp(pr.created_at),
            ctime=make_valid_timestamp(pr.created_at),
            deletions=pr.deletions,
            diff_url=pr.diff_url,
            draft=pr.draft,
            # head=pr.head,
            html_url=pr.html_url,
            pr_id=pr.id,
            issue_url=pr.issue_url,
            # labels=pr.labels,
            merge_commit_sha=pr.merge_commit_sha,
            mergeable=pr.mergeable,
            mergeable_state=pr.mergeable_state,
            merged=pr.merged,
            merged_at=make_valid_timestamp(pr.merged_at),
            # merged_by=pr.merged_by,
            # milestone=pr.milestone,
            number=pr.number,
            id=str(pr.number),
            patch_url=pr.patch_url,
            rebaseable=pr.rebaseable,
            review_comments=pr.review_comments,
            review_comments_url=pr.review_comments_url,
            state=pr.state,
            title=pr.title,
            updated_at=make_valid_timestamp(pr.updated_at),
            mtime=make_valid_timestamp(pr.updated_at),
            url=pr.url,
            # user=pr.user,
            maintainer_can_modify=pr.maintainer_can_modify,
        )


@define(eq=False, slots=False)
class GithubRepo(GithubResource, BaseResource):
    kind: ClassVar[str] = "github_repo"
    kind_display: ClassVar[str] = "Github Repository"
    kind_description: ClassVar[str] = "A Github Repository."

    allow_merge_commit: Optional[bool] = None
    allow_rebase_merge: Optional[bool] = None
    allow_squash_merge: Optional[bool] = None
    archived: Optional[bool] = None
    archive_url: Optional[str] = None
    assignees_url: Optional[str] = None
    blobs_url: Optional[str] = None
    branches_url: Optional[str] = None
    clone_url: Optional[str] = None
    clones_traffic: Optional[GithubRepoClonesTraffic] = None
    collaborators_url: Optional[str] = None
    comments_url: Optional[str] = None
    commits_url: Optional[str] = None
    compare_url: Optional[str] = None
    contents_url: Optional[str] = None
    contributors_count: Optional[int] = None
    contributors_url: Optional[str] = None
    created_at: Optional[datetime] = None
    default_branch: Optional[str] = None
    delete_branch_on_merge: Optional[bool] = None
    deployments_url: Optional[str] = None
    description: Optional[str] = None
    downloads_url: Optional[str] = None
    events_url: Optional[str] = None
    fork: Optional[bool] = None
    forks: Optional[int] = None
    forks_count: Optional[int] = None
    forks_url: Optional[str] = None
    full_name: Optional[str] = None
    git_commits_url: Optional[str] = None
    git_refs_url: Optional[str] = None
    git_tags_url: Optional[str] = None
    git_url: Optional[str] = None
    has_downloads: Optional[bool] = None
    has_issues: Optional[bool] = None
    has_pages: Optional[bool] = None
    has_projects: Optional[bool] = None
    has_wiki: Optional[bool] = None
    homepage: Optional[str] = None
    hooks_url: Optional[str] = None
    html_url: Optional[str] = None
    repo_id: Optional[int] = None
    issue_comment_url: Optional[str] = None
    issue_events_url: Optional[str] = None
    issues_url: Optional[str] = None
    keys_url: Optional[str] = None
    labels_url: Optional[str] = None
    language: Optional[str] = None
    languages_url: Optional[str] = None
    master_branch: Optional[str] = None
    merges_url: Optional[str] = None
    milestones_url: Optional[str] = None
    mirror_url: Optional[str] = None
    name: Optional[str] = None
    network_count: Optional[int] = None
    notifications_url: Optional[str] = None
    open_issues: Optional[int] = None
    open_issues_count: Optional[int] = None
    private: Optional[bool] = None
    pulls_url: Optional[str] = None
    pushed_at: Optional[datetime] = None
    releases_url: Optional[str] = None
    size: Optional[int] = None
    ssh_url: Optional[str] = None
    stargazers_count: Optional[int] = None
    stargazers_url: Optional[str] = None
    statuses_url: Optional[str] = None
    subscribers_count: Optional[int] = None
    subscribers_url: Optional[str] = None
    subscription_url: Optional[str] = None
    svn_url: Optional[str] = None
    tags_url: Optional[str] = None
    teams_url: Optional[str] = None
    top_paths: Optional[List[GithubRepoTopPath]] = None
    top_referrers: Optional[List[GithubRepoTopReferrer]] = None
    trees_url: Optional[str] = None
    updated_at: Optional[datetime] = None
    url: Optional[str] = None
    watchers: Optional[int] = None
    watchers_count: Optional[int] = None
    views_traffic: Optional[GithubRepoViewsTraffic] = None

    @staticmethod
    def new(repo: Repository):
        return GithubRepo(
            id=repo.name,
            name=repo.name,
            allow_merge_commit=repo.allow_merge_commit,
            allow_rebase_merge=repo.allow_rebase_merge,
            allow_squash_merge=repo.allow_squash_merge,
            archived=repo.archived,
            archive_url=repo.archive_url,
            assignees_url=repo.assignees_url,
            blobs_url=repo.blobs_url,
            branches_url=repo.branches_url,
            clone_url=repo.clone_url,
            collaborators_url=repo.collaborators_url,
            comments_url=repo.comments_url,
            commits_url=repo.commits_url,
            compare_url=repo.compare_url,
            contents_url=repo.contents_url,
            contributors_url=repo.contributors_url,
            created_at=make_valid_timestamp(repo.created_at),
            ctime=make_valid_timestamp(repo.created_at),
            default_branch=repo.default_branch,
            delete_branch_on_merge=repo.delete_branch_on_merge,
            deployments_url=repo.deployments_url,
            description=repo.description,
            downloads_url=repo.downloads_url,
            events_url=repo.events_url,
            fork=repo.fork,
            forks=repo.forks,
            forks_count=repo.forks_count,
            forks_url=repo.forks_url,
            full_name=repo.full_name,
            git_commits_url=repo.git_commits_url,
            git_refs_url=repo.git_refs_url,
            git_tags_url=repo.git_tags_url,
            git_url=repo.git_url,
            has_downloads=repo.has_downloads,
            has_issues=repo.has_issues,
            has_pages=repo.has_pages,
            has_projects=repo.has_projects,
            has_wiki=repo.has_wiki,
            homepage=repo.homepage,
            hooks_url=repo.hooks_url,
            html_url=repo.html_url,
            repo_id=repo.id,
            issue_comment_url=repo.issue_comment_url,
            issue_events_url=repo.issue_events_url,
            issues_url=repo.issues_url,
            keys_url=repo.keys_url,
            labels_url=repo.labels_url,
            language=repo.language,
            languages_url=repo.languages_url,
            master_branch=repo.master_branch,
            merges_url=repo.merges_url,
            milestones_url=repo.milestones_url,
            mirror_url=repo.mirror_url,
            network_count=repo.network_count,
            notifications_url=repo.notifications_url,
            open_issues=repo.open_issues,
            open_issues_count=repo.open_issues_count,
            private=repo.private,
            pulls_url=repo.pulls_url,
            pushed_at=make_valid_timestamp(repo.pushed_at),
            releases_url=repo.releases_url,
            size=repo.size,
            ssh_url=repo.ssh_url,
            stargazers_count=repo.stargazers_count,
            stargazers_url=repo.stargazers_url,
            statuses_url=repo.statuses_url,
            subscribers_count=repo.subscribers_count,
            subscribers_url=repo.subscribers_url,
            subscription_url=repo.subscription_url,
            svn_url=repo.svn_url,
            tags_url=repo.tags_url,
            teams_url=repo.teams_url,
            trees_url=repo.trees_url,
            updated_at=make_valid_timestamp(repo.updated_at),
            mtime=make_valid_timestamp(repo.updated_at),
            url=repo.url,
            watchers=repo.watchers,
            watchers_count=repo.watchers_count,
            clones_traffic=GithubRepoClonesTraffic.new(get_clones_traffic(repo)),
            views_traffic=GithubRepoViewsTraffic.new(get_views_traffic(repo)),
            top_referrers=[GithubRepoTopReferrer.new(referrer) for referrer in get_top_referrers(repo)],
            top_paths=[GithubRepoTopPath.new(path) for path in get_top_paths(repo)],
            contributors_count=len(list(repo.get_contributors())),
        )


def get_clones_traffic(repo: Repository) -> Optional[Dict[str, Union[int, List[Clones]]]]:
    try:
        return repo.get_clones_traffic()
    except GithubException as e:
        log.debug(f"Failed to get clones traffic for {repo.full_name}: {e}")
        return None


def get_views_traffic(repo: Repository) -> Optional[Dict[str, Union[int, List[View]]]]:
    try:
        return repo.get_views_traffic()
    except GithubException as e:
        log.debug(f"Failed to get views traffic for {repo.full_name}: {e}")
        return None


def get_top_referrers(repo: Repository) -> List[Referrer]:
    try:
        return repo.get_top_referrers()
    except GithubException as e:
        log.debug(f"Failed to get top referrers for {repo.full_name}: {e}")
        return []


def get_top_paths(repo: Repository) -> List[Path]:
    try:
        return repo.get_top_paths()
    except GithubException as e:
        log.debug(f"Failed to get top paths for {repo.full_name}: {e}")
        return []
