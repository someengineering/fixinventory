from pathlib import Path
from tempfile import NamedTemporaryFile

from fixshell.authorized_client import ReshConfig


def test_config() -> None:
    with NamedTemporaryFile() as file:
        config = ReshConfig(Path(file.name))
        config.set("section", "test", "some value")
        assert config.get("section", "test") == "some value"
        config.write()
        with open(file.name, "r") as f:
            assert f.read() == "[section]\ntest = some value\n\n"
