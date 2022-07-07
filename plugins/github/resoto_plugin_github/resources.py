from datetime import datetime
import resotolib.logger
from attrs import define
from typing import Optional, ClassVar
from resotolib.graph import Graph
from resotolib.baseresources import (
    BaseAccount,
    BaseRegion,
    BaseResource,
    BaseUser,
)
import github

log = resotolib.logger.getLogger("resoto." + __name__)


@define(eq=False, slots=False)
class GithubAccount(BaseAccount):
    kind: ClassVar[str] = "github_account"

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class GithubRegion(BaseRegion):
    kind: ClassVar[str] = "github_region"

    def delete(self, graph: Graph) -> bool:
        return False


@define(eq=False, slots=False)
class GithubResource:
    kind: ClassVar[str] = "github_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class GithubOrg(GithubResource, BaseResource):
    kind: ClassVar[str] = "github_org"

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
    def new(org: github.Organization.Organization) -> BaseResource:
        return GithubOrg(
            id=str(org.login),
            name=org.name,
            avatar_url=org.avatar_url,
            billing_email=org.billing_email,
            blog=org.blog,
            collaborators=org.collaborators,
            company=org.company,
            created_at=org.created_at,
            ctime=org.created_at,
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
            updated_at=org.updated_at,
            mtime=org.updated_at,
            url=org.url,
        )


@define(eq=False, slots=False)
class GithubUser(GithubResource, BaseUser):
    kind: ClassVar[str] = "github_user"

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
    def new(user: github.NamedUser.NamedUser) -> BaseResource:
        return GithubUser(
            id=str(user.login),
            avatar_url=user.avatar_url,
            bio=user.bio,
            blog=user.blog,
            collaborators=user.collaborators,
            company=user.company,
            contributions=user.contributions,
            created_at=user.created_at,
            ctime=user.created_at,
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
            suspended_at=user.suspended_at,
            team_count=user.team_count,
            total_private_repos=user.total_private_repos,
            twitter_username=user.twitter_username,
            user_type=user.type,
            updated_at=user.updated_at,
            mtime=user.updated_at,
            url=user.url,
        )


@define(eq=False, slots=False)
class GithubRepo(GithubResource, BaseResource):
    kind: ClassVar[str] = "github_repo"

    allow_merge_commit: Optional[bool] = None
    allow_rebase_merge: Optional[bool] = None
    allow_squash_merge: Optional[bool] = None
    archived: Optional[bool] = None
    archive_url: Optional[str] = None
    assignees_url: Optional[str] = None
    blobs_url: Optional[str] = None
    branches_url: Optional[str] = None
    clone_url: Optional[str] = None
    collaborators_url: Optional[str] = None
    comments_url: Optional[str] = None
    commits_url: Optional[str] = None
    compare_url: Optional[str] = None
    contents_url: Optional[str] = None
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
    trees_url: Optional[str] = None
    updated_at: Optional[datetime] = None
    url: Optional[str] = None
    watchers: Optional[int] = None
    watchers_count: Optional[int] = None

    @staticmethod
    def new(repo: github.Repository.Repository):
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
            created_at=repo.created_at,
            ctime=repo.created_at,
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
            pushed_at=repo.pushed_at,
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
            updated_at=repo.updated_at,
            mtime=repo.updated_at,
            url=repo.url,
            watchers=repo.watchers,
            watchers_count=repo.watchers_count,
        )
