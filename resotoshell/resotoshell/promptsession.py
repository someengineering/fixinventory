import logging
import pathlib
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, List, Dict, Union

from prompt_toolkit import PromptSession as PTSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import (
    Completer,
    CompleteEvent,
    Completion,
    WordCompleter,
    NestedCompleter,
    merge_completers,
    PathCompleter,
    FuzzyWordCompleter,
)
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style


def cut_document_remaining(document: Document, remaining: str) -> Document:
    return Document(
        remaining,
        cursor_position=document.cursor_position
        - (len(document.text) - len(remaining)),
    )


def cut_document_last(document: Document, last_part: str) -> Document:
    left, right = document.text_before_cursor.rsplit(last_part, 1)
    right_stripped = right.lstrip()
    return Document(
        right_stripped,
        cursor_position=document.cursor_position
        - len(left)
        - len(last_part)
        - (len(right) - len(right_stripped)),
    )


@dataclass
class ArgInfo:
    name: Optional[str]
    expects_value: bool = False
    possible_values: List[str] = field(default_factory=list)
    can_occur_multiple_times: bool = False
    value_hint: Optional[str] = None
    help_text: Optional[str] = None


SubCommands = Dict[str, Union["SubCommands", List[ArgInfo]]]


@dataclass
class CommandInfo:
    name: str
    options: List[ArgInfo] = field(default_factory=list)
    sub_commands: SubCommands = field(default_factory=dict)
    source: bool = True


@dataclass
class ArgCompleter(Completer):
    arg: ArgInfo
    completer: Optional[Completer]

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        if self.completer:
            return self.completer.get_completions(document, complete_event)
        else:
            return []


@dataclass
class CommandCompleter(Completer):
    cmd: CommandInfo
    completer: Optional[Completer]

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        if self.completer:
            return self.completer.get_completions(document, complete_event)
        else:
            return []


re_inside_is = re.compile("is\\(([^)]*)$")
# re_json_value = r'(?:"([^"]*)")|(?:\[[^\\]+\])|(?:\{[^}]+\})|(?:[A-Za-z0-9_\-:/.]+)'
# re_inside_filter = re.compile(
#     f".*(?:[A-Za-z_][A-Za-z0-9_\\-.\\[\\]]*)\\s*(?:==|=|!=|<|>|<=|>=|=~|~|!~|in|not in)\\s*(?:{re_json_value})$"
# )
param_start = re.compile(r".*(?:and|or)\s+([A-Za-z0-9_\-]*)$")


class SearchCompleter(Completer):
    def __init__(self, kinds: List[str], props: List[str]):
        self.kinds = kinds
        self.props = props
        self.kind_completer = FuzzyWordCompleter(kinds, WORD=True)
        self.props_completer = FuzzyWordCompleter(props, WORD=True)
        self.start_completer = WordCompleter(
            ["is", "all"],
            display_dict=(
                {
                    "is": "is(kind): matches elements of defined kind",
                    "all": "all: matches all elements",
                }
            ),
            WORD=True,
        )

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:

        text = document.text_before_cursor
        text_stripped = text.strip()

        if text_stripped == "is"[0 : len(text_stripped)]:
            return self.start_completer.get_completions(document, complete_event)
        elif in_is := re_inside_is.match(text):
            doc = cut_document_remaining(document, in_is.group(1))
            return self.kind_completer.get_completions(doc, complete_event)
        elif parm := param_start.match(text):
            doc = cut_document_remaining(document, parm.group(1))
            return self.props_completer.get_completions(doc, complete_event)
        else:
            return []


class ExampleCompleter(Completer):
    def __init__(self, *examples: str):
        self.examples = examples

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        # only provide one example
        if document.text_before_cursor == "":
            for example in self.examples:
                yield Completion(" ", start_position=0, display=example)


class ArgsCompleter(Completer):
    def __init__(self, args: List[ArgCompleter]):
        direct, opts = [], []
        for x in args:
            (direct if x.arg.name is None else opts).append(x)

        self.args: Dict[str, ArgCompleter] = {arg.arg.name: arg for arg in opts}

        # this completer completes new options as well as direct values
        self.completer = merge_completers(
            [
                FuzzyWordCompleter(list(self.args.keys()), WORD=True),
                *[a.completer for a in direct if a.completer],
            ]
        )
        self.value_lookup: Dict[str, ArgCompleter] = {
            v: a for a in args for v in a.arg.possible_values
        }

    def inside_option(self, parts: List[str]) -> Optional[ArgCompleter]:
        for idx, part in enumerate(reversed(parts)):
            if (parm := self.args.get(part)) is not None:
                return parm if parm.arg.expects_value and idx < 2 else None

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        parts = document.text_before_cursor.strip().split()
        maybe = self.inside_option(parts)
        if maybe is None:

            def allowed(completion: Completion) -> bool:
                txt = completion.text
                # has this parameter been specified before?
                if (
                    txt in parts
                    and txt in self.args
                    and not self.args[txt].arg.can_occur_multiple_times
                ):
                    return False
                # is this a possible value, where another value is already defined?
                if txt in self.value_lookup:
                    return not any(
                        v
                        for v in self.value_lookup[txt].arg.possible_values
                        if v in parts
                    )
                # if we come here: this is a valid completion
                return True

            return filter(
                allowed, self.completer.get_completions(document, complete_event)
            )
        else:
            # suggest the arg values
            doc = cut_document_last(document, maybe.arg.name)
            return maybe.get_completions(doc, complete_event)


class CommandLineCompleter(Completer):
    def __init__(self, commands: List[CommandInfo], completers: List[CommandCompleter]):
        self.commands = commands
        self.command_completers = {c.cmd.name: c for c in completers}
        self.source_completer = FuzzyWordCompleter(
            [c.name for c in commands if c.source], WORD=True
        )
        self.flow_completer = FuzzyWordCompleter(
            [c.name for c in commands if not c.source], WORD=True
        )

    def find_current_command(self, document: Document) -> Optional[CommandCompleter]:
        parts = document.text_before_cursor.strip().split()
        for part in reversed(parts):
            if (command := self.command_completers.get(part)) is not None:
                return command

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        text = document.text_before_cursor.lstrip()

        adapted = document
        if ";" in text:
            left, right = document.text.rsplit(";", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)
        elif "|" in text:
            left, right = document.text.rsplit("|", 1)
            adapted = Document(right, document.cursor_position - len(left) - 1)

        if not text.endswith((";", "|")):  # enforce a space after ; or |
            maybe = self.find_current_command(adapted)
            if maybe is not None:
                doc = cut_document_last(document, maybe.cmd.name)
                return maybe.get_completions(doc, complete_event)
            elif ";" in text or "|" in text:
                return self.flow_completer.get_completions(adapted, complete_event)
            else:
                return self.source_completer.get_completions(adapted, complete_event)

    @staticmethod
    def create_completer(
        cmds: List[CommandInfo], kinds: List[str], props: List[str]
    ) -> "CommandLineCompleter":
        def arg_completer(arg: ArgInfo) -> Optional[Completer]:
            if arg.possible_values:
                return FuzzyWordCompleter(arg.possible_values, WORD=True)
            elif arg.value_hint == "file":
                return PathCompleter()
            elif arg.value_hint == "kind":
                return FuzzyWordCompleter(kinds, WORD=True)
            elif arg.value_hint == "property":
                return FuzzyWordCompleter(props, WORD=True)
            elif arg.value_hint == "search":
                return SearchCompleter(kinds, props)
            elif arg.help_text:
                return ExampleCompleter(arg.help_text)
            else:
                return ExampleCompleter("<value>")

        def arg_value_completer(arg: ArgInfo) -> ArgCompleter:
            return ArgCompleter(arg, arg_completer(arg))

        def command_completer(cmd: CommandInfo) -> Optional[Completer]:
            assert cmd.options != cmd.sub_commands

            def walk_commands(sub_commands: SubCommands) -> Completer:
                return NestedCompleter.from_nested_dict(
                    {
                        sub_cmd: ArgsCompleter(
                            [arg_value_completer(arg) for arg in options]
                        )
                        if isinstance(options, list)
                        else walk_commands(options)
                        for sub_cmd, options in sub_commands.items()
                    }
                )

            if cmd.options:
                return ArgsCompleter([arg_value_completer(arg) for arg in cmd.options])
            elif cmd.sub_commands:
                return walk_commands(cmd.sub_commands)
            else:
                return None

        cmd_completer = [CommandCompleter(cmd, command_completer(cmd)) for cmd in cmds]
        return CommandLineCompleter(cmds, cmd_completer)


known_kinds = [
    "access_key",
    "account",
    "autoscaling_group",
    "aws_account",
    "aws_alb",
    "aws_alb_quota",
    "aws_alb_target_group",
    "aws_autoscaling_group",
    "aws_cloudformation_stack",
    "aws_cloudformation_stack_set",
    "aws_cloudwatch_alarm",
    "aws_ec2_elastic_ip",
    "aws_ec2_instance",
    "aws_ec2_instance_quota",
    "aws_ec2_instance_type",
    "aws_ec2_internet_gateway",
    "aws_ec2_internet_gateway_quota",
    "aws_ec2_keypair",
    "aws_ec2_nat_gateway",
    "aws_ec2_network_acl",
    "aws_ec2_network_interface",
    "aws_ec2_route_table",
    "aws_ec2_security_group",
    "aws_ec2_snapshot",
    "aws_ec2_subnet",
    "aws_ec2_volume",
    "aws_ec2_volume_type",
    "aws_eks_cluster",
    "aws_eks_nodegroup",
    "aws_elb",
    "aws_elb_quota",
    "aws_iam_access_key",
    "aws_iam_group",
    "aws_iam_instance_profile",
    "aws_iam_policy",
    "aws_iam_role",
    "aws_iam_server_certificate",
    "aws_iam_server_certificate_quota",
    "aws_iam_user",
    "aws_rds_instance",
    "aws_region",
    "aws_resource",
    "aws_s3_bucket",
    "aws_s3_bucket_quota",
    "aws_vpc",
    "aws_vpc_endpoint",
    "aws_vpc_peering_connection",
    "aws_vpc_quota",
    "base_cloud",
    "bucket",
    "bucket_quota",
    "certificate",
    "certificate_quota",
    "cloud",
    "database",
    "digitalocean_alert_policy",
    "digitalocean_app",
    "digitalocean_cdn_endpoint",
    "digitalocean_certificate",
    "digitalocean_container_registry",
    "digitalocean_container_registry_repository",
    "digitalocean_container_registry_repository_tag",
    "digitalocean_database",
    "digitalocean_domain",
    "digitalocean_domain_record",
    "digitalocean_droplet",
    "digitalocean_firewall",
    "digitalocean_floating_ip",
    "digitalocean_image",
    "digitalocean_kubernetes_cluster",
    "digitalocean_load_balancer",
    "digitalocean_network",
    "digitalocean_project",
    "digitalocean_region",
    "digitalocean_resource",
    "digitalocean_snapshot",
    "digitalocean_space",
    "digitalocean_ssh_key",
    "digitalocean_tag",
    "digitalocean_team",
    "digitalocean_volume",
    "domain",
    "domain_record",
    "endpoint",
    "example_account",
    "example_custom_resource",
    "example_instance",
    "example_network",
    "example_region",
    "example_resource",
    "example_volume",
    "gateway",
    "gateway_quota",
    "gcp_autoscaler",
    "gcp_backend_service",
    "gcp_bucket",
    "gcp_database",
    "gcp_disk",
    "gcp_disk_type",
    "gcp_forwarding_rule",
    "gcp_gke_cluster",
    "gcp_global_forwarding_rule",
    "gcp_global_network_endpoint_group",
    "gcp_health_check",
    "gcp_http_health_check",
    "gcp_https_health_check",
    "gcp_instance",
    "gcp_instance_group",
    "gcp_instance_group_manager",
    "gcp_instance_template",
    "gcp_machine_type",
    "gcp_network",
    "gcp_network_endpoint_group",
    "gcp_project",
    "gcp_quota",
    "gcp_region",
    "gcp_resource",
    "gcp_route",
    "gcp_router",
    "gcp_security_policy",
    "gcp_service",
    "gcp_service_sku",
    "gcp_snapshot",
    "gcp_ssl_certificate",
    "gcp_subnetwork",
    "gcp_target_grpc_proxy",
    "gcp_target_http_proxy",
    "gcp_target_https_proxy",
    "gcp_target_instance",
    "gcp_target_pool",
    "gcp_target_ssl_proxy",
    "gcp_target_tcp_proxy",
    "gcp_target_vpn_gateway",
    "gcp_url_map",
    "gcp_vpn_gateway",
    "gcp_vpn_tunnel",
    "gcp_zone",
    "github_account",
    "github_org",
    "github_region",
    "github_repo",
    "github_resource",
    "github_user",
    "graph_root",
    "group",
    "health_check",
    "instance",
    "instance_profile",
    "instance_quota",
    "instance_type",
    "ip_address",
    "keypair",
    "kubernetes_cluster",
    "kubernetes_controller_revision",
    "kubernetes_daemon_set",
    "kubernetes_deployment",
    "kubernetes_horizontal_pod_autoscaler",
    "kubernetes_namespace",
    "kubernetes_node",
    "kubernetes_pod",
    "kubernetes_replica_set",
    "kubernetes_resource",
    "kubernetes_stateful_set",
    "load_balancer",
    "load_balancer_quota",
    "network",
    "network_acl",
    "network_interface",
    "network_quota",
    "onelogin_account",
    "onelogin_region",
    "onelogin_resource",
    "onelogin_user",
    "onprem_instance",
    "onprem_location",
    "onprem_network",
    "onprem_region",
    "onprem_resource",
    "peering_connection",
    "phantom_resource",
    "policy",
    "predefined_properties",
    "quota",
    "region",
    "resource",
    "role",
    "routing_table",
    "security_group",
    "slack_conversation",
    "slack_region",
    "slack_resource",
    "slack_team",
    "slack_user",
    "slack_usergroup",
    "snapshot",
    "stack",
    "subnet",
    "test_cpl",
    "tunnel",
    "type",
    "unknown_account",
    "unknown_cloud",
    "unknown_location",
    "unknown_region",
    "unknown_zone",
    "user",
    "volume",
    "volume_type",
    "vsphere_cluster",
    "vsphere_data_center",
    "vsphere_instance",
    "vsphere_resource",
    "zone",
]
known_props = [
    "access_key_last_used_region",
    "access_key_last_used_service_name",
    "access_key_status",
    "account_access_keys_present",
    "account_alias",
    "account_mfa_enabled",
    "account_signing_certificates_present",
    "actions_enabled",
    "activated_at",
    "age",
    "alarm_actions",
    "alarm_description",
    "allocation_id",
    "allow_merge_commit",
    "allow_rebase_merge",
    "allow_squash_merge",
    "allow_users_to_change_password",
    "archive_url",
    "archived",
    "arn",
    "assignees_url",
    "association_id",
    "atime",
    "auto_provision",
    "auto_type",
    "auto_upgrade_enabled",
    "avatar_url",
    "backends",
    "billing_email",
    "bio",
    "blobs_url",
    "blog",
    "branches_url",
    "bucket_location",
    "bucket_location_type",
    "certificate",
    "certificate_id",
    "certificate_managed",
    "certificate_state",
    "certificate_type",
    "check_interval",
    "clone_url",
    "cluster_endpoint",
    "cluster_name",
    "cluster_status",
    "collaborators",
    "collaborators_url",
    "color",
    "comment",
    "comments_url",
    "commits_url",
    "company",
    "compare_url",
    "comparison_operator",
    "compressed_size_bytes",
    "contents_url",
    "contributions",
    "contributors_url",
    "created_at",
    "created_by",
    "creator",
    "ctime",
    "current_master_version",
    "current_node_count",
    "custom_attributes",
    "custom_dict_attribute",
    "custom_domain",
    "custom_int_attribute",
    "custom_list_attribute",
    "custom_optional_float_attribute",
    "custom_string_attribute",
    "db_endpoint",
    "db_publicly_accessible",
    "db_status",
    "db_type",
    "db_version",
    "default_branch",
    "default_ingress",
    "default_port",
    "default_repository_permission",
    "delete_branch_on_merge",
    "deleted",
    "department",
    "deployments_url",
    "description",
    "dimensions",
    "directory_id",
    "disable_lets_encrypt_dns_records",
    "disk_usage",
    "display_name",
    "display_name_normalized",
    "distinguished_name",
    "distribution",
    "dns_names",
    "do_region_droplet_sizes",
    "do_region_features",
    "do_region_slug",
    "domain",
    "domain_name",
    "downloads_url",
    "droplet_backup_ids",
    "droplet_features",
    "droplet_image",
    "email",
    "email_domain",
    "enable_backend_keepalive",
    "enable_proxy_protocol",
    "encrypted",
    "endpoint",
    "enterprise_subteam_id",
    "environment",
    "evaluation_periods",
    "events_url",
    "expire_passwords",
    "expires",
    "external_id",
    "failover_ratio",
    "filesystem_label",
    "filesystem_type",
    "fingerprint",
    "firewall_status",
    "first_name",
    "firstname",
    "followers",
    "followers_url",
    "following",
    "following_url",
    "fork",
    "forks",
    "forks_count",
    "forks_url",
    "full_name",
    "geo_taxonomy_regions",
    "geo_taxonomy_type",
    "gists_url",
    "git_commits_url",
    "git_refs_url",
    "git_tags_url",
    "git_url",
    "global_endpoint_token_version",
    "gravatar_id",
    "group_id",
    "group_policies",
    "groups",
    "guest_invited_by",
    "ha_enabled",
    "handle",
    "hard_expiry",
    "has_downloads",
    "has_issues",
    "has_organization_projects",
    "has_pages",
    "has_projects",
    "has_repository_projects",
    "has_wiki",
    "health_check_type",
    "healthy_threshold",
    "hireable",
    "homepage",
    "hooks_url",
    "host",
    "html_url",
    "icon",
    "id",
    "image_192",
    "image_24",
    "image_32",
    "image_48",
    "image_512",
    "image_72",
    "image_slug",
    "image_status",
    "image_type",
    "initial_cluster_version",
    "instance_cores",
    "instance_id",
    "instance_memory",
    "instance_status",
    "instance_type",
    "insufficient_data_actions",
    "invalid_login_attempts",
    "invitation_sent_at",
    "invitation_teams_url",
    "ip_address",
    "ip_address_family",
    "ip_protocol",
    "ip_range",
    "ipv4_address",
    "is_admin",
    "is_app_user",
    "is_archived",
    "is_available",
    "is_bot",
    "is_channel",
    "is_default",
    "is_enabled",
    "is_ext_shared",
    "is_external",
    "is_general",
    "is_group",
    "is_im",
    "is_locked",
    "is_member",
    "is_mpim",
    "is_org_shared",
    "is_owner",
    "is_pending_ext_shared",
    "is_primary_owner",
    "is_private",
    "is_public",
    "is_read_only",
    "is_restricted",
    "is_shared",
    "is_subteam",
    "is_ultra_restricted",
    "is_usergroup",
    "issue_comment_url",
    "issue_events_url",
    "issues_url",
    "k8s_cluster_subnet",
    "k8s_service_subnet",
    "k8s_version",
    "keys_url",
    "kind",
    "label_fingerprint",
    "labels_url",
    "language",
    "languages_url",
    "last_access",
    "last_attach_timestamp",
    "last_detach_timestamp",
    "last_login",
    "last_name",
    "last_update",
    "lastname",
    "lb_type",
    "link",
    "live_domain",
    "live_url",
    "live_url_base",
    "load_balancing_scheme",
    "loadbalancer_status",
    "locale_code",
    "locked_until",
    "login",
    "mac",
    "manager_ad_id",
    "manager_user_id",
    "manifest_count",
    "manifest_digest",
    "master_branch",
    "max_password_age",
    "max_replicas",
    "max_size",
    "member_of",
    "members_can_create_repositories",
    "members_url",
    "merges_url",
    "metric_name",
    "mfa_devices",
    "mfa_devices_in_use",
    "milestones_url",
    "min_disk_size",
    "min_replicas",
    "min_size",
    "minimum_password_length",
    "mirror_url",
    "mtime",
    "name",
    "name_normalized",
    "namespace",
    "nat_gateway_status",
    "neg_type",
    "network_count",
    "network_device",
    "network_interface_id",
    "network_interface_owner_id",
    "network_interface_status",
    "network_interface_type",
    "network_interfaces",
    "network_ip4",
    "network_ip6",
    "network_tier",
    "node_id",
    "nodegroup_status",
    "notifications_url",
    "nr_nodes",
    "num_members",
    "ok_actions",
    "ondemand_cost",
    "open_issues",
    "open_issues_count",
    "openid_name",
    "org_id",
    "org_location",
    "org_type",
    "organizations_url",
    "origin",
    "ot",
    "owned_private_repos",
    "owner_alias",
    "owner_id",
    "owner_uuid",
    "parent_conversation",
    "password_age",
    "password_changed_at",
    "password_reuse_prevention",
    "path",
    "pending_connected_team_ids",
    "pending_shared",
    "period",
    "phone",
    "policies",
    "policy_type",
    "policy_versions_in_use",
    "port",
    "port_range",
    "previous_names",
    "pricing_info",
    "private",
    "private_gists",
    "private_ip_address",
    "private_ips",
    "public_gists",
    "public_ip",
    "public_ip_address",
    "public_ips",
    "public_key",
    "public_members_url",
    "public_repos",
    "pulls_url",
    "purpose",
    "purpose_creator",
    "purpose_last_set",
    "pushed_at",
    "quota",
    "quota_type",
    "real_name",
    "real_name_normalized",
    "received_events_url",
    "record_data",
    "record_flags",
    "record_name",
    "record_port",
    "record_priority",
    "record_tag",
    "record_ttl",
    "record_type",
    "record_weight",
    "redirect_http_to_https",
    "region_status",
    "registry_enabled",
    "registry_name",
    "releases_url",
    "replicas",
    "repo_id",
    "repos_url",
    "repository_name",
    "request_path",
    "require_lowercase_characters",
    "require_numbers",
    "require_symbols",
    "require_uppercase_characters",
    "reservations",
    "resource_family",
    "resource_group",
    "resource_id",
    "resource_type",
    "role",
    "role_ids",
    "role_policies",
    "samaccountname",
    "self_link",
    "server_certificates",
    "service",
    "service_provider_name",
    "session_affinity",
    "sha1_fingerprint",
    "shared_team_ids",
    "site_admin",
    "size",
    "size_bytes",
    "size_gigabytes",
    "skype",
    "snapshot_before_delete",
    "snapshot_size_gigabytes",
    "snapshot_status",
    "ssh_url",
    "stack_parameters",
    "stack_set_administration_role_arn",
    "stack_set_auto_deployment",
    "stack_set_capabilities",
    "stack_set_drift_detection_details",
    "stack_set_execution_role_name",
    "stack_set_last_drift_check_timestamp",
    "stack_set_managed_execution_active",
    "stack_set_organizational_unit_ids",
    "stack_set_parameters",
    "stack_set_permission_model",
    "stack_set_status",
    "stack_status",
    "stack_status_reason",
    "stargazers_count",
    "stargazers_url",
    "starred_url",
    "state",
    "state_value",
    "statistic",
    "status",
    "status_emoji",
    "status_expiration",
    "status_text",
    "status_text_canonical",
    "statuses_url",
    "storage_bytes",
    "storage_class",
    "storage_usage_bytes",
    "subject_alternative_names",
    "subscribers_count",
    "subscribers_url",
    "subscription_url",
    "subscriptions_url",
    "surge_upgrade_enabled",
    "suspended_at",
    "svn_url",
    "tag_count",
    "tags",
    "tags_url",
    "target_type",
    "team_count",
    "team_id",
    "teams_url",
    "threshold",
    "tier_slug",
    "timeout",
    "title",
    "topic",
    "topic_creator",
    "topic_last_set",
    "total_private_repos",
    "trees_url",
    "trusted_idp_id",
    "ttl",
    "twitter_username",
    "two_factor_requirement_enabled",
    "tz",
    "tz_label",
    "tz_offset",
    "unhealthy_threshold",
    "unlinked",
    "updated_at",
    "updated_by",
    "url",
    "urn",
    "usage",
    "usage_type",
    "user_count",
    "user_id",
    "user_location",
    "user_name",
    "user_policies",
    "user_type",
    "username",
    "userprincipalname",
    "users",
    "v6_ips",
    "volume_encrypted",
    "volume_id",
    "volume_iops",
    "volume_kms_key_id",
    "volume_multi_attach_enabled",
    "volume_outpost_arn",
    "volume_size",
    "volume_snapshot_id",
    "volume_status",
    "volume_throughput",
    "volume_type",
    "vpc_endpoint_status",
    "vpc_endpoint_type",
    "vpc_peering_connection_status",
    "watchers",
    "watchers_count",
    "zone_file",
    "zone_separation",
    "zone_status",
]
known_commands = [
    CommandInfo("aggregate", source=False),
    CommandInfo(
        "ancestors",
        options=[
            ArgInfo("--with-origin"),
            ArgInfo(None, True, ["default", "delete"], help_text="edge type"),
        ],
        source=False,
    ),
    CommandInfo(
        "certificate",
        sub_commands={
            "create": [
                ArgInfo(
                    "--common-name", True, help_text="Common name like: example.com"
                ),
                ArgInfo(
                    "--dns-names",
                    True,
                    help_text="List of other dns names: example.org example.io",
                ),
                ArgInfo(
                    "--ip-addresses",
                    True,
                    help_text="List of ip addresses: 1.2.3.4 2.3.4.5",
                ),
            ],
            "delete": [],
        },
    ),
    CommandInfo(
        "configs",
        sub_commands={
            "list": [],
            "set": [
                ArgInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
            "show": [
                ArgInfo(
                    None, expects_value=True, help_text="<config_id> e.g. resoto.core"
                )
            ],
            "edit": [
                ArgInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
            "update": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<config_id> /path/to/config.yaml",
                ),
            ],
            "delete": [
                ArgInfo(
                    None, expects_value=True, help_text="<config_id> <key>=<value>"
                ),
            ],
        },
    ),
    CommandInfo(
        "chunk",
        [
            ArgInfo(
                None, expects_value=True, help_text="number of elements in the chunk"
            )
        ],
        source=False,
    ),
    CommandInfo(
        "clean",
        [ArgInfo(None, expects_value=True, help_text="optional reason for cleaning")],
        source=False,
    ),
    CommandInfo(
        "count",
        [ArgInfo(None, expects_value=True, help_text="optional property to count")],
        source=False,
    ),
    CommandInfo(
        "descendants",
        options=[
            ArgInfo("--with-origin"),
            ArgInfo(None, True, ["default", "delete"], help_text="edge type"),
        ],
        source=False,
    ),
    CommandInfo("dump", source=False),
    CommandInfo(
        "echo",
        [ArgInfo(None, expects_value=True, help_text="the text to echo")],
    ),
    CommandInfo("env"),
    CommandInfo("flatten", source=False),
    CommandInfo(
        "format",
        [
            ArgInfo(
                None,
                possible_values=[
                    "--json",
                    "--ndjson",
                    "--text",
                    "--cytoscape",
                    "--graphml",
                    "--dot",
                ],
            ),
            ArgInfo(
                None,
                expects_value=True,
                help_text="format definition with {} placeholders.",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "head",
        options=[
            ArgInfo(None, True, help_text="the number of elements to return. e.g. -10"),
        ],
        source=False,
    ),
    CommandInfo(
        "http",
        [
            ArgInfo("--compress"),
            ArgInfo("--timeout", expects_value=True),
            ArgInfo("--no-ssl-verify"),
            ArgInfo("--no-body"),
            ArgInfo("--nr-of-retries", expects_value=True),
            ArgInfo(
                None,
                expects_value=True,
                help_text="<method> <url> <headers> <query_params>",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "jobs",
        sub_commands={
            "add": [
                ArgInfo("--id", expects_value=True),
                ArgInfo("--schedule", expects_value=True),
                ArgInfo("--wait-for-event", expects_value=True),
                ArgInfo("--timeout", expects_value=True),
                ArgInfo(None, help_text="<command> to run"),
            ],
            "show": [
                ArgInfo(None, help_text="<job-id>"),
            ],
            "list": [],
            "update": [
                ArgInfo(None, help_text="<job-id>"),
                ArgInfo("--schedule", expects_value=True),
                ArgInfo("--wait-for-event", expects_value=True),
            ],
            "delete": [
                ArgInfo(None, help_text="<job-id>"),
            ],
            "activate": [
                ArgInfo(None, help_text="<job-id>"),
            ],
            "deactivate": [
                ArgInfo(None, help_text="<job-id>"),
            ],
            "run": [
                ArgInfo(None, help_text="<job-id>"),
            ],
            "running": [],
        },
    ),
    CommandInfo(
        "json",
        [
            ArgInfo(None, expects_value=True, help_text="json expression."),
        ],
    ),
    CommandInfo(
        "jq",
        [
            ArgInfo("--no-rewrite"),
            ArgInfo(None, expects_value=True, help_text="the text to echo"),
        ],
        source=False,
    ),
    CommandInfo(
        "kinds",
        [
            ArgInfo("-p", expects_value=True, value_hint="property"),
            ArgInfo(
                None,
                expects_value=True,
                help_text="the name of the kind",
                value_hint="kind",
            ),
        ],
    ),
    CommandInfo(
        "list",
        [
            ArgInfo(None, possible_values=["--csv", "--markdown"], help_text="format"),
            ArgInfo(
                None,
                expects_value=True,
                help_text="the list of properties, comma separated",
            ),
        ],
        source=False,
    ),
    CommandInfo(
        "predecessors",
        options=[
            ArgInfo("--with-origin"),
            ArgInfo(None, True, ["default", "delete"], help_text="edge type"),
        ],
        source=False,
    ),
    CommandInfo("protect", source=False),
    CommandInfo("search", options=[ArgInfo(None, True, value_hint="search")]),
    CommandInfo(
        "set_desired",
        options=[
            ArgInfo(None, True, help_text="<prop>=<value>"),
        ],
        source=False,
    ),
    CommandInfo(
        "set_metadata",
        options=[
            ArgInfo(None, True, help_text="<prop>=<value>"),
        ],
        source=False,
    ),
    CommandInfo(
        "sleep",
        options=[
            ArgInfo(None, True, help_text="time to sleep in seconds"),
        ],
    ),
    CommandInfo(
        "successors",
        options=[
            ArgInfo("--with-origin"),
            ArgInfo(None, True, ["default", "delete"], help_text="edge type"),
        ],
        source=False,
    ),
    CommandInfo(
        "system",
        sub_commands={
            "backup": {
                "create": [
                    ArgInfo(
                        None,
                        expects_value=True,
                        help_text="The name of the backup file.",
                        value_hint="file",
                    ),
                ],
                "restore": [
                    ArgInfo(
                        None,
                        expects_value=True,
                        help_text="The name of the local backup file to upload.",
                        value_hint="file",
                    ),
                ],
            },
            "info": [],
        },
    ),
    CommandInfo(
        "tag",
        sub_commands={
            "update": [
                ArgInfo("--nowait"),
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<tag-name> <tag-value>",
                ),
            ],
            "delete": [
                ArgInfo("--nowait"),
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<tag-name>",
                ),
            ],
        },
        source=False,
    ),
    CommandInfo(
        "tail",
        options=[
            ArgInfo(None, True, help_text="the number of elements to return. e.g. -10"),
        ],
        source=False,
    ),
    CommandInfo(
        "templates",
        sub_commands={
            "add": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<name> <template>",
                ),
            ],
            "delete": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<name>",
                ),
            ],
            "test": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<key1>=<value1>, ..., <keyN>=<valueN> <template>",
                ),
            ],
            "update": [
                ArgInfo(
                    None,
                    expects_value=True,
                    help_text="<name> <template>",
                ),
            ],
        },
    ),
    CommandInfo("unique", source=False),
    CommandInfo(
        "workflows",
        sub_commands={
            "show": [
                ArgInfo(None, help_text="<workflow-id>"),
            ],
            "list": [],
            "run": [
                ArgInfo(None, help_text="<workflow-id>"),
            ],
            "running": [],
        },
    ),
    CommandInfo(
        "write",
        [ArgInfo(None, value_hint="file", help_text="<filename> to write to")],
        source=False,
    ),
]


class PromptSession:

    style = Style.from_dict(
        {
            "green": "#00ff00",
            "red": "#ff0000",
            "prompt": "#C724B1",
        }
    )

    prompt_message = [("class:prompt", "> ")]

    def __init__(
        self, history_file: str = str(pathlib.Path.home() / ".resotoshell_history")
    ):
        history = FileHistory(history_file)
        self.completer = CommandLineCompleter.create_completer(
            known_commands, known_kinds, known_props
        )
        self.session = PTSession(history=history)

    def prompt(self) -> str:
        try:
            return self.session.prompt(
                self.prompt_message,
                completer=self.completer,
                complete_while_typing=True,
                style=self.style,
                auto_suggest=AutoSuggestFromHistory(),
            )
        except (TypeError, AttributeError) as ex:
            raise KeyboardInterrupt from ex
