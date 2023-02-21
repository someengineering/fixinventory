from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import os
from attrs import evolve, frozen
from pytest import fixture

from resotocore import core_config
from resotocore.core_config import (
    parse_config,
    CoreConfig,
    ApiConfig,
    config_model,
    EditableConfig,
    WorkflowConfig,
    migrate_core_config,
    migrate_command_config,
    CustomCommandsConfig,
    alias_templates,
    ResotoCoreCommandsRoot,
)
from resotocore.dependencies import parse_args
from resotocore.model.typed_model import to_js, from_js
from resotocore.types import Json
from resotocore.util import value_in_path
from typing import Any


def test_parse_empty(default_config: CoreConfig) -> None:
    result = parse_config(parse_args(["--analytics-opt-out"]), {})
    assert result == default_config


def test_parse_broken(config_json: Json) -> None:
    # config_json is a valid parsable config
    cfg = deepcopy(config_json)

    # adjust the config: rename web_hosts -> hosts, and web_port -> port
    hosts = cfg["resotocore"]["api"]["web_hosts"]
    port = cfg["resotocore"]["api"]["web_port"]
    cfg["resotocore"]["api"]["hosts"] = hosts
    cfg["resotocore"]["api"]["port"] = port
    del cfg["resotocore"]["api"]["web_hosts"]
    del cfg["resotocore"]["api"]["web_port"]

    # parse this configuration
    parsed = parse_config(parse_args(["--analytics-opt-out"]), cfg)
    parsed_json = to_js(parsed.editable, strip_attr="kind")

    # web_hosts and web_port were not available and are reverted to the default values
    default = EditableConfig()
    assert parsed.api.web_hosts != hosts
    assert parsed.api.web_hosts == default.api.web_hosts
    assert parsed.api.web_port != port
    assert parsed.api.web_port == default.api.web_port

    # other config values are still unchanged
    assert parsed_json["cli"] == config_json["resotocore"]["cli"]
    assert parsed_json["runtime"] == config_json["resotocore"]["runtime"]
    assert parsed_json["graph_update"] == config_json["resotocore"]["graph_update"]


def test_read_config(config_json: Json) -> None:
    parsed = parse_config(parse_args(["--analytics-opt-out"]), config_json)
    assert parsed.json() == config_json


def test_override_via_cmd_line(default_config: CoreConfig) -> None:
    config = {"runtime": {"debug": False}}
    parsed = parse_config(parse_args(["--debug"]), config)
    assert parsed.runtime.debug == True


# noinspection PyTypeChecker
def test_validate() -> None:
    assert EditableConfig().validate() is None
    assert EditableConfig(api=ApiConfig(tsdb_proxy_url="wrong")).validate() == {
        "api": [{"tsdb_proxy_url": ["url is missing host", "url is missing scheme"]}]
    }
    assert EditableConfig(api=ApiConfig(max_request_size=1)).validate() == {
        "api": [{"max_request_size": ["min value is 1048576"]}]
    }
    assert EditableConfig(api=ApiConfig(tsdb_proxy_url="wrong", max_request_size=1)).validate() == {
        "api": [
            {
                "tsdb_proxy_url": ["url is missing host", "url is missing scheme"],
                "max_request_size": ["min value is 1048576"],
            }
        ]
    }
    assert EditableConfig(workflows={"foo": WorkflowConfig("bla")}).validate() == {
        "workflows": [{"foo": [{"schedule": ["Invalid cron expression: Wrong number of fields; got 1, expected 5"]}]}]
    }


def test_config_override(config_json: Json) -> None:
    # config_json is a valid parsable config
    cfg = deepcopy(config_json)

    # create a temp file with a custom config
    with TemporaryDirectory() as tmp:
        # config with env var override
        resotocore_1_conf = Path(tmp, "resotocore.yml")
        resotocore_1_conf.write_text(
            """
resotocore:
    api:
        web_hosts: ["11.12.13.14"]
        """,
            encoding="utf-8",
        )

        # config that overrides the default config and containes an env var which can't be resolved
        resotocore_2_conf = Path(tmp, "resotocore-1.yml")
        resotocore_2_conf.write_text(
            """
resotocore:
    api:
        web_port: $(WEB_PORT)
        web_path: "$(DO_NOT_REPLACE_ME)"
        """
        )

        resotoworker_conf = Path(tmp, "resotoworker.yml")
        resotoworker_conf.write_text(
            """
resotoworker:
  collector: ['digitalocean', '$(OTHER_COLLECTOR)']
            """
        )

        os.environ["WEB_PORT"] = "1337"

        # parse this configuration
        parsed = parse_config(
            parse_args(
                ["--analytics-opt-out", "--override-path", str(tmp)]
            ),
            cfg,
        )
        assert parsed.api.web_hosts == ["11.12.13.14"]
        assert parsed.api.web_port == 1337
        assert parsed.api.web_path == "$(DO_NOT_REPLACE_ME)"

        assert parsed.overrides == {
            "resotocore": {
                "api": {"web_hosts": ["11.12.13.14"], "web_port": "$(WEB_PORT)", "web_path": "$(DO_NOT_REPLACE_ME)"}
            },
            "resotoworker": {
                "collector": ['digitalocean', '$(OTHER_COLLECTOR)']
            }
        }


def test_model() -> None:
    model = config_model()
    assert {m["fqn"] for m in model} == {
        "custom_commands",
        "resotocore",
        "resotocore_api_config",
        "resotocore_certificate_config",
        "resotocore_cli_alias_template",
        "resotocore_cli_alias_template_parameter",
        "resotocore_cli_config",
        "resotocore_graph_update_config",
        "resotocore_runtime_config",
        "resotocore_workflow_config",
    }


def test_in_docker() -> None:
    with TemporaryDirectory() as tmp:
        path = Path(tmp, "git.hash")
        path.write_text("foo", encoding="utf-8")
        stored = core_config.GitHashFile
        core_config.GitHashFile = str(path)
        assert core_config.inside_docker() is True
        assert core_config.git_hash_from_file() == "foo"
        assert core_config.default_hosts() == ["0.0.0.0"]
        core_config.GitHashFile = "/this/path/does/not/exist"
        assert core_config.inside_docker() is False
        assert core_config.git_hash_from_file() is None
        assert core_config.default_hosts() == ["localhost"]
        core_config.GitHashFile = stored


def test_migration() -> None:
    cfg1 = migrate_core_config(dict(resotocore=dict(runtime=dict(analytics_opt_out=True))))
    assert value_in_path(cfg1, "resotocore.runtime.usage_metrics") is False
    assert value_in_path(cfg1, "resotocore.runtime.analytics_opt_out") is None
    cfg2 = migrate_core_config(dict(resotocore=dict(runtime=dict(usage_metrics=True))))
    assert value_in_path(cfg2, "resotocore.runtime.usage_metrics") is True
    assert value_in_path(cfg1, "resotocore.runtime.analytics_opt_out") is None
    cfg3 = migrate_core_config(dict(resotocore=dict(runtime=dict(analytics_opt_out=True, usage_metrics=True))))
    assert value_in_path(cfg3, "resotocore.runtime.usage_metrics") is True
    assert value_in_path(cfg1, "resotocore.runtime.analytics_opt_out") is None


def test_migrate_commands() -> None:
    # default configuration does not need migration
    assert migrate_command_config(CustomCommandsConfig().json()) is None
    # an empty configuration is migrated to the default configuration
    assert migrate_command_config(CustomCommandsConfig(commands=[]).json()) == CustomCommandsConfig().json()
    # an existing configuration is not destroyed
    example = evolve(alias_templates()[0], name="my-test-cmd")
    custom = CustomCommandsConfig(commands=[example])
    migrated_json: Json = migrate_command_config(custom.json())  # type: ignore
    assert migrated_json != custom.json()
    migrated = from_js(migrated_json.get(ResotoCoreCommandsRoot), CustomCommandsConfig)
    assert any(cmd == example for cmd in migrated.commands)
    assert len(migrated.commands) == len(alias_templates()) + 1


@fixture
def config_json() -> Json:
    return {
        "resotocore": {
            "api": {
                "web_hosts": ["1.2.3.4"],
                "web_port": 1234,
                "web_path": "/",
                "tsdb_proxy_url": "test",
                "max_request_size": 5242880,
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
            "graph_update": {"abort_after_seconds": 1234, "merge_max_wait_time_seconds": 4321, "keep_history": True},
            "runtime": {
                "usage_metrics": False,
                "debug": True,
                "log_level": "WARN",
                "plantuml_server": "https://foo",
                "start_collect_on_subscriber_connect": True,
            },
            "workflows": {
                "collect_and_cleanup": {
                    "schedule": "0 0 0 0 *",
                }
            },
        }
    }
