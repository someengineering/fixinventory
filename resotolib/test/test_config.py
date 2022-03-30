import pytest
from dataclasses import dataclass, field
from typing import Optional, ClassVar
from resotolib.config import Config, ConfigNotFoundError
from resotolib.args import get_arg_parser
from resotolib.core import add_args as core_add_args


def test_config():
    arg_parser = get_arg_parser()
    core_add_args(arg_parser)
    arg_parser.parse_args()
    cfg = Config("test")
    cfg.add_config(ConfigTest)
    cfg.init_default_config()
    assert Config.dict() == {
        "configtest": {"testvar1": "testing123", "testvar2": 12345}
    }
    cfg2 = Config("test2")
    assert cfg.configtest.testvar1 == cfg2.configtest.testvar1
    assert cfg.configtest.testvar1 == Config.configtest.testvar1
    assert cfg.configtest.testvar2 == cfg2.configtest.testvar2
    Config.configtest.testvar2 += 1
    assert cfg.configtest.testvar2 == 12346
    with pytest.raises(ConfigNotFoundError):
        Config.does_not_exist.foo = "bar"
    with pytest.raises(ConfigNotFoundError):
        cfg.does_not_exist.foo = "bar"


@dataclass
class ConfigTest:
    kind: ClassVar[str] = "configtest"
    testvar1: Optional[str] = field(
        default="testing123", metadata={"description": "A test string"}
    )
    testvar2: Optional[int] = field(
        default=12345, metadata={"description": "A test integer"}
    )
