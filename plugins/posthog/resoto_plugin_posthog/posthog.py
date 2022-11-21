from typing import Optional, List

import requests

from .resources import PosthogProject, PosthogEvent


class PosthogAPI:
    def __init__(self, api_key: str, url: str) -> None:
        self.api_key = api_key
        self.projects_api = f"{url}/api/projects"

    def project(self, pro: str) -> PosthogProject:
        """Returns a PosthogProject given a project name"""
        next = self.projects_api

        while next is not None:
            r = self._get(next)
            for p in r.get("results"):
                if p.get("name") == pro:
                    data = self._get(f"{self.projects_api}/{p.get('id')}")
                    return PosthogProject.new(data)

            next = r.get("next")

    def events(self, project_id: int) -> List[PosthogEvent]:
        """Return all event definitions for a specific posthog project"""
        next = f"{self.projects_api}/{project_id}/event_definitions"
        events: List[PosthogEvent] = []

        while next is not None:
            r = self._get(next)

            for event in r.get("results"):
                data = event
                data["project_id"] = project_id
                e = PosthogEvent.new(data)
                events.append(e)

            next = r.get("next")

        for event in events:
            metrics = self.insights(event, "-1h")
            event.count = int(metrics.get("result")[0].get("count"))

        return events

    def insights(self, event: PosthogEvent, since: str):
        uri = f"{self.projects_api}/{event.project_id}/insights/trend/"
        params = {
            "insight": "TRENDS",
            "events": [{"id": event.name, "name": event.name, "order": 0}],
            "date_from": since,
        }
        r = self._get(uri, headers={"Content-Type": "application/json"}, params=params)
        return r

    def _get(self, uri: str, headers: Optional[dict] = {}, params: Optional[dict] = None) -> Optional[dict]:
        auth_headers = {"Authorization": f"Bearer {self.api_key}"}
        headers.update(auth_headers)
        r = requests.get(uri, headers=headers, json=params)
        if r.status_code != 200:
            raise RuntimeError(f"Error requesting insights: {uri} {r.text} ({r.status_code})")

        return r.json()
