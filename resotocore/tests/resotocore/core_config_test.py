from pathlib import Path
from tempfile import TemporaryDirectory

from pytest import fixture

from resotocore import core_config
from resotocore.core_config import (
    parse_config,
    CoreConfig,
    ApiConfig,
    CLIConfig,
    DatabaseConfig,
    GraphUpdateConfig,
    RuntimeConfig,
    config_model,
    EditableConfig,
)
from resotocore.dependencies import parse_args


def test_parse_empty(default_config: CoreConfig) -> None:
    result = parse_config(parse_args(["--analytics-opt-out"]), {})
    assert result == default_config


def test_read_config() -> None:
    config = {
        "resotocore": {
            "api": {
                "web_hosts": ["1.2.3.4"],
                "web_port": 1234,
                "web_path": "/",
                "tsdb_proxy_url": "test",
                "ui_path": "fest",
                "host_certificate": {
                    "common_name": "test",
                    "san_dns_names": ["test.example.com"],
                    "san_ip_addresses": ["4.3.2.1"],
                    "include_loopback": False,
                },
            },
            "cli": {
                "default_graph": "foo",
                "default_section": "bla",
                "alias_templates": [
                    {
                        "info": "Test command",
                        "name": "test",
                        "parameters": [{"name": "test", "default": "test argument", "description": "easy"}],
                        "template": "do something",
                    }
                ],
            },
            "graph_update": {"abort_after_seconds": 1234, "merge_max_wait_time_seconds": 4321},
            "runtime": {
                "analytics_opt_out": True,
                "debug": True,
                "log_level": "WARN",
                "plantuml_server": "https://foo",
                "start_collect_on_subscriber_connect": True,
            },
        }
    }
    parsed = parse_config(parse_args(["--analytics-opt-out"]), config)
    assert parsed.json() == config


def test_override_via_cmd_line(default_config: CoreConfig) -> None:
    config = {"runtime": {"debug": False}}
    parsed = parse_config(parse_args(["--debug"]), config)
    assert parsed.runtime.debug == True


# noinspection PyTypeChecker
def test_validate() -> None:
    assert EditableConfig().validate() is None
    assert EditableConfig(api=ApiConfig(ui_path=True)).validate() == {  # type: ignore
        "api": [{"ui_path": ["must be of string type"]}]
    }
    assert EditableConfig(api=ApiConfig(ui_path="does not exist")).validate() == {
        "api": [{"ui_path": ["Path does not exist: does not exist"]}]
    }
    assert EditableConfig(api=ApiConfig(ui_path="does not exist", tsdb_proxy_url="wrong")).validate() == {
        "api": [
            {
                "tsdb_proxy_url": ["url is missing scheme", "url is missing host"],
                "ui_path": ["Path does not exist: does not exist"],
            }
        ]
    }


def test_model() -> None:
    model = config_model()
    assert {m["fqn"] for m in model} == {
        "resotocore",
        "resotocore_api_config",
        "resotocore_certificate_config",
        "resotocore_cli_config",
        "resotocore_cli_alias_template",
        "resotocore_cli_alias_template_parameter",
        "resotocore_graph_update_config",
        "resotocore_runtime_config",
    }


def test_in_docker() -> None:
    with TemporaryDirectory() as tmp:
        path = Path(tmp, "config.yaml")
        path.write_text("foo", encoding="utf-8")
        stored = core_config.GitHashFile
        core_config.GitHashFile = str(path)
        assert core_config.inside_docker() is True
        assert core_config.git_hash_from_file() == "foo"
        assert core_config.default_nic() == ["0.0.0.0"]
        core_config.GitHashFile = "/this/path/does/not/exist"
        assert core_config.inside_docker() is False
        assert core_config.git_hash_from_file() is None
        assert core_config.default_nic() == ["localhost"]
        core_config.GitHashFile = stored


@fixture
def default_config() -> CoreConfig:
    return CoreConfig(
        api=ApiConfig(),
        cli=CLIConfig(),
        db=DatabaseConfig(),
        graph_update=GraphUpdateConfig(),
        # We use this flag explicitly - otherwise it is picked up by env vars
        runtime=RuntimeConfig(analytics_opt_out=True),
        args=parse_args(["--analytics-opt-out"]),
    )
