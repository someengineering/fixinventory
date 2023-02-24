from pathlib import Path
from tempfile import TemporaryDirectory
from resotocore.config.config_override_service import ConfigOverrideService
import os
from resotocore.ids import ConfigId
import pytest
from typing import Optional, Any
from resotocore.types import Json
import asyncio


def test_get_overrides() -> None:
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
        web_path: "$(DO_NOT_REPLACE_ME)"
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

        override_service = ConfigOverrideService([Path(tmp)])

        assert override_service.get_override(ConfigId("resoto.core")) == {
            "resotocore": {
                "api": {
                    "web_hosts": ["11.12.13.14"],
                    "web_port": "$(WEB_PORT)",
                    "web_path": "$(DO_NOT_REPLACE_ME)",
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
                        "web_path": "$(DO_NOT_REPLACE_ME)",
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

        override_service = ConfigOverrideService([Path(tmp)], sleep_time=0.05)
        override_service.watch_for_changes()
        await asyncio.sleep(0.25)  # wait for the watcher to start

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
