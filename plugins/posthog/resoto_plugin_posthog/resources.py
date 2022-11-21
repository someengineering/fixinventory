from datetime import datetime
from attrs import define
from typing import Optional, ClassVar, List, Dict
from resotolib.graph import Graph
from resotolib.baseresources import BaseAccount, BaseResource


@define(eq=False, slots=False)
class PosthogResource:
    kind: ClassVar[str] = "posthog_resource"

    def delete(self, graph: Graph) -> bool:
        return False

    def update_tag(self, key, value) -> bool:
        return False

    def delete_tag(self, key) -> bool:
        return False


@define(eq=False, slots=False)
class PosthogProject(PosthogResource, BaseAccount):
    kind: ClassVar[str] = "posthog_project"

    project_id: int
    app_urls: Optional[List[str]] = (None,)
    slack_incoming_webhook: Optional[List[str]] = (None,)
    anonymize_ips: Optional[bool] = (None,)
    completed_snippet_onboarding: Optional[bool] = (None,)
    timezone: Optional[str] = (None,)
    test_account_filters: Optional[object] = (None,)
    test_account_filters_default_checked: Optional[bool] = (None,)
    path_cleaning_filters: Optional[object] = (None,)
    data_attributes: Optional[object] = (None,)
    person_display_name_properties: Optional[List[str]] = (None,)
    correlation_config: Optional[Dict] = (None,)
    session_recording_opt_in: Optional[bool] = (None,)
    access_control: Optional[bool] = (None,)
    primary_dashboard: Optional[int] = (None,)
    live_events_columns: Optional[List[str]] = (None,)
    recording_domains: Optional[List[str]] = None

    @staticmethod
    def new(data: Dict) -> "PosthogProject":
        return PosthogProject(
            id=data.get("uuid"),
            project_id=data.get("id"),
            name=data.get("name"),
            mtime=convert_date(data.get("updated_at")),
            ctime=convert_date(data.get("created_at")),
            app_urls=data.get("app_urls"),
            slack_incoming_webhook=data.get("slack_incoming_webhook"),
            anonymize_ips=data.get("anonymize_ips"),
            completed_snippet_onboarding=data.get("completed_snippet_onboarding"),
            timezone=data.get("timezone"),
            test_account_filters=data.get("test_account_filters"),
            test_account_filters_default_checked=data.get("test_account_filters_default_checked"),
            path_cleaning_filters=data.get("path_cleaning_filters"),
            data_attributes=data.get("data_attributes"),
            person_display_name_properties=data.get("person_display_name_properties"),
            correlation_config=data.get("correlation_config"),
            session_recording_opt_in=data.get("session_recording_opt_in"),
            access_control=data.get("access_control"),
            primary_dashboard=data.get("primary_dashboard"),
            live_events_columns=data.get("live_events_columns"),
            recording_domains=data.get("recording_domains"),
        )


@define(eq=False, slots=False)
class PosthogEvent(PosthogResource, BaseResource):
    kind: ClassVar[str] = "posthog_event"

    project_id: int
    count: int = 0
    description: Optional[str] = None
    posthog_tags: Optional[List[str]] = None
    volume_30_day: Optional[int] = None
    query_usage_30_day: Optional[int] = None
    is_action: Optional[bool] = None
    action_id: Optional[int] = None
    last_seen_at: Optional[str] = None
    verified: Optional[bool] = None
    verified_at: Optional[str] = None
    is_calculating: Optional[bool] = None
    last_calculated_at: Optional[str] = None
    post_to_slack: Optional[bool] = None

    @staticmethod
    def new(data: Dict) -> BaseResource:
        return PosthogEvent(
            id=data.get("id"),
            name=data.get("name"),
            mtime=convert_date(data.get("last_updated_at")),
            ctime=convert_date(data.get("created_at")),
            project_id=data.get("project_id"),
            description=data.get("description"),
            volume_30_day=data.get("volume_30_day"),
            query_usage_30_day=data.get("query_usage_30_day"),
            is_action=data.get("is_action"),
            action_id=data.get("action_id"),
            is_calculating=data.get("is_calculating"),
            last_calculated_at=data.get("last_calculated_at"),
            post_to_slack=data.get("post_to_slack"),
        )


def convert_date(date_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
