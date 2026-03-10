from typing import Any, Optional

from google.auth.credentials import AnonymousCredentials

from fix_plugin_gcp.gcp_client import GcpApiSpec, GcpClient


class FakeRequest:
    def __init__(self, page_number: int) -> None:
        self.page_number = page_number

    def execute(self) -> dict[str, list[dict[str, int]]]:
        return {"items": [{"page": self.page_number}]}


class FakeFindingsExecutor:
    _baseUrl = "https://securitycenter.googleapis.com/"

    def __init__(self, pages: int) -> None:
        self.pages = pages

    def projects(self) -> "FakeFindingsExecutor":
        return self

    def sources(self) -> "FakeFindingsExecutor":
        return self

    def findings(self) -> "FakeFindingsExecutor":
        return self

    def list(self, **_: Any) -> FakeRequest:
        return FakeRequest(0)

    def list_next(self, previous_request: FakeRequest, previous_response: Any) -> Optional[FakeRequest]:
        del previous_response
        next_page = previous_request.page_number + 1
        if next_page < self.pages:
            return FakeRequest(next_page)
        return None


def test_gcp_client_list_handles_many_pages(monkeypatch: Any) -> None:
    def fake_discovery(service: str, version: str, credentials: Any, cache: Any) -> FakeFindingsExecutor:
        del service, version, credentials, cache
        return FakeFindingsExecutor(1500)

    monkeypatch.setattr("fix_plugin_gcp.gcp_client._discovery_function", fake_discovery)

    api_spec = GcpApiSpec(
        service="securitycenter",
        version="v1",
        accessors=["projects", "sources", "findings"],
        action="list",
        request_parameter={"parent": "projects/{project}/sources/-"},
        request_parameter_in={"project"},
        response_path="items",
    )

    client = GcpClient(AnonymousCredentials(), project_id="test-project")  # type: ignore[arg-type]
    result = client.list(api_spec)

    assert len(result) == 1500
    assert result[0]["page"] == 0
    assert result[-1]["page"] == 1499