from resotocore.validator import Validator


def test_path_exist() -> None:
    v = Validator()
    assert v.validate({"path": "does not exist"}, {"path": {"path_exists": True}}) is False
    assert v.errors == {"path": ["Path does not exist: does not exist"]}
    v = Validator()
    assert v.validate({"path": "/"}, {"path": {"path_exists": True}}) is True


def test_is_url() -> None:
    v = Validator()
    assert v.validate({"url": "does not exist"}, {"url": {"is_url": True}}) is False
    assert v.errors == {"url": ["url is missing host", "url is missing scheme"]}
    v = Validator()
    assert v.validate({"url": "https://resoto.com"}, {"url": {"is_url": True}}) is True
