from pytest import fixture

from resotocore.core_config import (
    parse_config,
    CoreConfig,
    ApiConfig,
    CLIConfig,
    DatabaseConfig,
    GraphUpdateConfig,
    RuntimeConfig,
    config_model,
)
from resotocore.dependencies import parse_args


def test_parse_empty(default_config: CoreConfig) -> None:
    result = parse_config(parse_args(["--analytics-opt-out"]), {})
    assert result == default_config


def test_read_config() -> None:
    config = {
        "resotocore": {
            "api": {"hosts": ["1.2.3.4"], "port": 1234, "psk": "test", "tsdb_proxy_url": "test", "ui_path": "fest"},
            "cli": {"default_graph": "foo", "default_section": "bla"},
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
    config = {"api": {"hosts": ["1.2.3.4"], "port": 1234}}
    parsed = parse_config(parse_args(["--host", "4.3.2.1", "--port", "4321"]), config)
    assert parsed.api.hosts == ["4.3.2.1"]
    assert parsed.api.port == 4321


def test_model() -> None:
    model = config_model()
    assert {m["fqn"] for m in model} == {
        "resotocore",
        "resotocore_api_config",
        "resotocore_cli_config",
        "resotocore_graph_update_config",
        "resotocore_runtime_config",
    }


@fixture
def default_config() -> CoreConfig:
    return CoreConfig(
        api=ApiConfig(hosts=["localhost"], port=8900, tsdb_proxy_url=None, ui_path=None, psk=None),
        cli=CLIConfig(default_graph="resoto", default_section="reported"),
        db=DatabaseConfig(
            server="http://localhost:8529",
            database="resoto",
            username="resoto",
            password="",
            root_password="",
            bootstrap_do_not_secure=False,
            no_ssl_verify=False,
            request_timeout=900,
        ),
        graph_update=GraphUpdateConfig(merge_max_wait_time_seconds=3600, abort_after_seconds=14400),
        runtime=RuntimeConfig(
            analytics_opt_out=True,
            debug=False,
            log_level="INFO",
            plantuml_server="http://plantuml.resoto.org:8080",
            start_collect_on_subscriber_connect=False,
        ),
        # We use this flag explicitly - otherwise it is picked up by env vars
        args=parse_args(["--analytics-opt-out"]),
    )
