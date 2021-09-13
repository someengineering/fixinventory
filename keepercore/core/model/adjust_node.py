import logging
from abc import ABC, abstractmethod
from typing import Optional

from core.model.model import DateTimeKind
from core.types import Json
from core.util import value_in_path, from_utc

log = logging.getLogger(__name__)


class AdjustNode(ABC):
    @abstractmethod
    def adjust(self, json: Json) -> Json:
        pass


class NoAdjust(AdjustNode):
    def adjust(self, json: Json) -> Json:
        return json


class DirectAdjuster(AdjustNode):
    dt = DateTimeKind("datetime")
    expiration_values = [
        ["reported", "tags", "cloudkeeper:expiration"],
        ["reported", "tags", "cloudkeeper:expires"],
        ["reported", "tags", "expires"],
        ["reported", "tags", "expiration"],
    ]

    def adjust(self, json: Json) -> Json:
        def expires_tag() -> Optional[str]:
            for path in self.expiration_values:
                expiration: Optional[str] = value_in_path(json, path)
                if expiration:
                    return expiration
            return None

        expires_in = expires_tag()
        if expires_in:
            try:
                if DateTimeKind.DurationRe.fullmatch(expires_in):
                    ctime = from_utc(json["reported"]["ctime"])
                    expires = DateTimeKind.from_duration(expires_in, ctime)
                else:
                    expires = self.dt.coerce(expires_in)
                if "metadata" not in json:
                    json["metadata"] = {}
                json["metadata"]["expires"] = expires
            except Exception as ex:
                log.info(f"Could not parse expires {ex}")
        # json is mutated to save memory
        return json
