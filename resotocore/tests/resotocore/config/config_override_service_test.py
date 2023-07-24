from pathlib import Path
from tempfile import TemporaryDirectory
from resotocore.config.config_override_service import ConfigOverrideService
import os
from resotocore.ids import ConfigId
import pytest
from typing import Optional, Any
from resotocore.types import Json
import asyncio
from resotocore.model.model import Model, ComplexKind, Property


@pytest.mark.asyncio
async def test_get_overrides() -> None:
    # create a temp file with a custom config
    with TemporaryDirectory() as tmp:
        # config with env var override
        resotocore_1_conf = Path(tmp, "resoto.core.yml")
        resotocore_1_conf.write_text(
            """
resotocore:
    api:
        web_hosts: ["11.12.13.14"]
        web_port: $(WEB_PORT)
        """,
            encoding="utf-8",
        )

        resotoworker_conf = Path(tmp, "resoto.worker.yml")
        resotoworker_conf.write_text(
            """
resotoworker:
    collector: ['digitalocean', '$(OTHER_COLLECTOR)']
            """
        )

        os.environ["WEB_PORT"] = "1337"

        async def get_configs_model() -> Model:
            return Model.empty()

        override_service = ConfigOverrideService([Path(tmp)], get_configs_model)
        await override_service.load()

        assert override_service.get_override(ConfigId("resoto.core")) == {
            "resotocore": {
                "api": {
                    "web_hosts": ["11.12.13.14"],
                    "web_port": "$(WEB_PORT)",
                }
            }
        }

        assert override_service.get_override(ConfigId("resoto.worker")) == {
            "resotoworker": {"collector": ["digitalocean", "$(OTHER_COLLECTOR)"]}
        }

        assert override_service.get_all_overrides() == {
            "resoto.core": {
                "resotocore": {
                    "api": {
                        "web_hosts": ["11.12.13.14"],
                        "web_port": "$(WEB_PORT)",
                    }
                }
            },
            "resoto.worker": {"resotoworker": {"collector": ["digitalocean", "$(OTHER_COLLECTOR)"]}},
        }


@pytest.mark.asyncio
async def test_hooks() -> None:
    # create a temp file with a custom config
    with TemporaryDirectory() as tmp:
        # config with env var override
        foo_conf = Path(tmp, "foo.yml")
        foo_conf.write_text(
            """
bar:
    foo: 42
        """,
            encoding="utf-8",
        )

        async def get_configs_model() -> Model:
            return Model.empty()

        override_service = ConfigOverrideService([Path(tmp)], get_configs_model, sleep_time=0.05)
        await override_service.load()
        await override_service.start()

        override_update: Optional[Json] = None

        async def update_hook(json: Any) -> None:
            nonlocal override_update
            override_update = json

        override_service.add_override_change_hook(update_hook)

        assert not override_update

        foo_conf.write_text(
            """
bar:
    foo: 1337
        """,
            encoding="utf-8",
        )

        await asyncio.sleep(0.25)  # wait for the watcher to update the config
        assert override_update == {"foo": {"bar": {"foo": 1337}}}


@pytest.mark.asyncio
async def test_validation() -> None:
    # create a temp file with a custom config
    with TemporaryDirectory() as tmp:
        # config with env var override
        resotocore_1_conf = Path(tmp, "resoto.core.yml")
        resotocore_1_conf.write_text(
            """
foo:
    bar: 42
    kind: foo""",
            encoding="utf-8",
        )

        foo_kinds = ComplexKind(
            "foo", [], [Property("bar", "int32", required=True), Property("kind", "string", required=True)]
        )

        async def get_configs_model() -> Model:
            return Model.from_kinds([foo_kinds])

        override_service = ConfigOverrideService([Path(tmp)], get_configs_model)
        await override_service.load()

        assert override_service.get_override(ConfigId("resoto.core")) == {
            "foo": {
                "bar": 42,
                "kind": "foo",
            }
        }

        resotocore_1_conf.write_text(
            """
foo:
    bar: bar
    kind: foo""",
            encoding="utf-8",
        )

        override_service = ConfigOverrideService([Path(tmp)], get_configs_model)
        await override_service.load()

        # invalid config should be ignored
        assert override_service.get_override(ConfigId("resoto.core")) is None

        resotocore_1_conf.write_text(
            """
foo:
    bar: 42""",
            encoding="utf-8",
        )
        override_service = ConfigOverrideService([Path(tmp)], get_configs_model)
        await override_service.load()

        # missing keys are allowed for overrides
        assert override_service.get_override(ConfigId("resoto.core")) == {
            "foo": {
                "bar": 42,
            }
        }


@pytest.mark.asyncio
async def test_load_json() -> None:
    # create a temp file with a custom config
    with TemporaryDirectory() as tmp:
        # config with env var override
        resotocore_1_conf = Path(tmp, "resoto.core.json")
        resotocore_1_conf.write_text(
            """
{
    "resotocore": {
        "api": {
            "web_hosts": ["11.12.13.14"],
            "web_port": "$(WEB_PORT)"
        }
    }
}""",
            encoding="utf-8",
        )

        resotoworker_conf = Path(tmp, "resoto.worker.json")
        resotoworker_conf.write_text(
            """
{
    "resotoworker": {
        "collector": ["digitalocean", "$(OTHER_COLLECTOR)"]
    }
}"""
        )

        os.environ["WEB_PORT"] = "1337"

        async def get_configs_model() -> Model:
            return Model.empty()

        override_service = ConfigOverrideService([Path(tmp)], get_configs_model)
        await override_service.load()

        assert override_service.get_override(ConfigId("resoto.core")) == {
            "resotocore": {
                "api": {
                    "web_hosts": ["11.12.13.14"],
                    "web_port": "$(WEB_PORT)",
                }
            }
        }

        assert override_service.get_override(ConfigId("resoto.worker")) == {
            "resotoworker": {"collector": ["digitalocean", "$(OTHER_COLLECTOR)"]}
        }

        assert override_service.get_all_overrides() == {
            "resoto.core": {
                "resotocore": {
                    "api": {
                        "web_hosts": ["11.12.13.14"],
                        "web_port": "$(WEB_PORT)",
                    }
                }
            },
            "resoto.worker": {"resotoworker": {"collector": ["digitalocean", "$(OTHER_COLLECTOR)"]}},
        }
