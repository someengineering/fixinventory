from pathlib import Path
from urllib import parse

from apscheduler.triggers.cron import CronTrigger
from cerberus import Validator as ValidatorBase


def schema_name(clazz: type) -> str:
    return clazz.__name__


class Validator(ValidatorBase):  # type: ignore
    """
    Only here to define custom validations.
    See: https://docs.python-cerberus.org/en/stable/customize.html
    """

    def _validate_path_exists(self, _: bool, field: str, value: str) -> None:
        """
        {'type': 'boolean'}
        """
        if value:
            if not Path(value).exists():
                self._error(field, f"Path does not exist: {value}")

    def _validate_is_url(self, _: bool, field: str, value: str) -> None:
        """
        {'type': 'boolean'}
        """
        if value:
            parsed = parse.urlparse(value, allow_fragments=False)
            if not parsed.scheme:
                self._error(field, "url is missing scheme")
            if not parsed.netloc:
                self._error(field, "url is missing host")

    def _validate_is_cron(self, _: bool, field: str, value: str) -> None:
        """
        {'type': 'boolean'}
        """
        if value:
            try:
                CronTrigger.from_crontab(value)
            except Exception as ex:
                self._error(field, f"Invalid cron expression: {ex}")
