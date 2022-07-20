from copy import deepcopy
from distutils.command.config import config
from functools import lru_cache
import pytest
from attrs import define, field
from typing import ClassVar, Dict
from resotolib.config import Config, ConfigNotFoundError
from resotolib.args import get_arg_parser, ArgumentParser
from resotolib.core import add_args as core_add_args


def test_config():
    arg_parser = get_arg_parser()
    core_add_args(arg_parser)
    arg_parser.parse_known_args()
    cfg = Config("test")
    cfg.add_config(ConfigTest)
    cfg.init_default_config()
    assert Config.dict() == {
        "configtest": {
            "testvar1": "testing123",
            "testvar2": 12345,
            "testvar3": {
                "mydict": {"foo": "bar", "abc": {"def": "ghi"}},
                "myint": 0,
                "mystr": "Hello",
            },
        }
    }
    cfg2 = Config("test2")
    assert cfg.configtest.testvar1 == cfg2.configtest.testvar1
    assert cfg.configtest.testvar1 == Config.configtest.testvar1
    assert cfg.configtest.testvar2 == cfg2.configtest.testvar2
    assert cfg.configtest.testvar3 == cfg2.configtest.testvar3
    Config.configtest.testvar2 += 1
    assert cfg.configtest.testvar2 == 12346
    with pytest.raises(ConfigNotFoundError):
        Config.does_not_exist.foo = "bar"
    with pytest.raises(ConfigNotFoundError):
        cfg.does_not_exist.foo = "bar"


def test_config_lru_cache():
    @lru_cache()
    def test_lru_config(config: Config):
        return config.configtest.testvar1

    arg_parser = get_arg_parser()
    core_add_args(arg_parser)
    arg_parser.parse_known_args()
    cfg = Config("test")
    cfg.add_config(ConfigTest)
    cfg.init_default_config()
    assert test_lru_config(cfg) == "testing123"
    # update config
    cfg.running_config.data["configtest"].testvar1 = "foo"
    cfg.running_config.revision = "foo_revision"
    assert cfg.configtest.testvar1 == "foo"
    assert test_lru_config(cfg) == "foo"
    # cleanup
    cfg.running_config.data["configtest"].testvar1 = "testing123"


def test_config_override():
    arg_parser = get_arg_parser()
    core_add_args(arg_parser)
    arg_parser.parse_known_args()
    cfg = Config("test")
    cfg.add_config(ConfigTest)
    cfg.init_default_config()
    assert Config.dict() == {
        "configtest": {
            "testvar1": "testing123",
            "testvar2": 12346,
            "testvar3": {
                "mydict": {"foo": "bar", "abc": {"def": "ghi"}},
                "myint": 0,
                "mystr": "Hello",
            },
        }
    }
    ArgumentParser.args.config_override = [
        "configtest.testvar1=testing124",
        "configtest.testvar3.myint=1",
        "configtest.testvar3.mystr=World",
        "configtest.testvar3.mydict.foo=baz",
        "configtest.testvar3.mydict.abc.def=jkl",
    ]
    cfg.override_config(cfg.running_config)
    assert Config.dict() == {
        "configtest": {
            "testvar1": "testing124",
            "testvar2": 12346,
            "testvar3": {
                "mydict": {"foo": "baz", "abc": {"def": "jkl"}},
                "myint": 1,
                "mystr": "World",
            },
        }
    }


@define
class NestedConfigTest:
    kind: ClassVar[str] = "nested_config_test"
    myint: int = field(default=0, metadata={"description": "My Int"})
    mystr: str = field(default="Hello", metadata={"description": "My String"})
    mydict: Dict[str, str] = field(factory=lambda: {"foo": "bar", "abc": {"def": "ghi"}})


@define
class ConfigTest:
    kind: ClassVar[str] = "configtest"
    testvar1: str = field(default="testing123", metadata={"description": "A test string"})
    testvar2: int = field(default=12345, metadata={"description": "A test integer"})
    testvar3: NestedConfigTest = field(
        factory=lambda: NestedConfigTest(),
        metadata={"description": "A test of nested config"},
    )
