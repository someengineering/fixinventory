from __future__ import annotations

from typing import List

from attr import define

from resotolib.types import Json


@define
class ProgressInfo:
    current: int
    total: int

    @property
    def percentage(self) -> int:
        return int(self.current * 100 / self.total)

    @property
    def done(self) -> bool:
        return self.current == self.total


@define
class Progress:
    name: str

    @property
    def percentage(self) -> int:
        return self.overall_progress().percentage

    def overall_progress(self) -> ProgressInfo:
        if isinstance(self, ProgressDone):
            return ProgressInfo(self.current, self.total)
        elif isinstance(self, ProgressList):
            total_max = (
                max(self.parts, key=lambda x: x.overall_progress().total).overall_progress().total if self.parts else 1
            )
            current = 0
            total = 0
            for part in self.parts:
                info = part.overall_progress()
                current += int(info.current * total_max / info.total)
                total += total_max
            return ProgressInfo(current, total)
        else:
            raise AttributeError("No handler to compute overall progress")

    def to_json(self) -> Json:
        if isinstance(self, ProgressDone):
            return {"kind": "progress", "name": self.name, "current": self.current, "total": self.total}
        elif isinstance(self, ProgressList):
            return {"kind": "info", "name": self.name, "parts": [part.to_json() for part in self.parts]}
        else:
            raise AttributeError("No handler to marshal progress")

    def info_json(self) -> Json:
        if isinstance(self, ProgressDone):
            return {self.name: {"current": self.current, "total": self.total}}
        elif isinstance(self, ProgressList):
            return {self.name: [part.info_json() for part in self.parts]}
        else:
            raise AttributeError("No handler to marshal progress")

    @staticmethod
    def from_json(json: Json) -> Progress:
        if json["kind"] == "progress":
            return ProgressDone(json["name"], json["current"], json["total"])
        elif json["kind"] == "info":
            return ProgressList(json["name"], [Progress.from_json(part) for part in json["parts"]])
        else:
            raise AttributeError("No handler to unmarshal progress")


@define
class ProgressDone(Progress):
    current: int
    total: int

    def __attrs_post_init__(self):
        if self.total <= 0:
            raise ValueError("total must be greater than 0")
        if self.current > self.total:
            raise ValueError(f"current ({self.current}) > total ({self.total})")

    def __str__(self) -> str:
        return f"{self.current}/{self.total}"


@define
class ProgressList(Progress):
    parts: List[Progress]
