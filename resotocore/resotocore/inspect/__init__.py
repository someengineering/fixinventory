from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict

from attr import define, field

from resotocore.types import Json
from resotolib.json import from_json

log = logging.getLogger(__name__)


class InspectionSeverity(Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@define
class Remediation:
    action: Dict[str, str]
    text: str
    url: str


@define
class InspectionCheck:
    id: str
    provider: str
    service: str
    title: str
    kind: str
    categories: List[str]
    severity: InspectionSeverity
    detect: Dict[str, str]
    remediation: Remediation
    url: Optional[str] = None
    related: List[str] = field(factory=list)

    @staticmethod
    def from_files() -> List[InspectionCheck]:
        def inspection(pdr: str, svc: str, check: Json) -> InspectionCheck:
            return InspectionCheck(
                id=f'{pdr}_{svc}_{check["name"]}',
                provider=pdr,
                service=svc,
                kind=check["kind"],
                title=check["title"],
                categories=check["categories"],
                severity=InspectionSeverity(check["severity"]),
                detect=check["detect"],
                remediation=Remediation(
                    action=check["remediation"].get("action", {}),
                    text=check["remediation"]["text"],
                    url=check["remediation"]["url"],
                ),
                url=check.get("url"),
                related=check.get("related", []),
            )

        def from_file(path: str) -> List[InspectionCheck]:
            with open(path, "rt", encoding="utf-8") as f:
                js = json.load(f)
                pdr = js["provider"]
                svc = js["service"]
                return [inspection(pdr, svc, check) for check in js["checks"]]

        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../inspect/checks")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for service in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                result.extend(from_file(service))
        return result


@define
class CheckCollection:
    title: str
    description: str
    documentation: Optional[str] = field(default=None, kw_only=True)
    checks: Optional[List[str]] = field(default=None, kw_only=True)
    children: Optional[List[CheckCollection]] = field(default=None, kw_only=True)

    def is_valid(self, inspections: Dict[str, InspectionCheck]) -> bool:
        return (
            not (self.children and self.checks)
            and all(c in inspections for c in self.checks or [])
            and all(c.is_valid(inspections) for c in self.children or [])
        )


@define
class Benchmark(CheckCollection):
    framework: str
    version: str

    @staticmethod
    def from_files(inspections: Dict[str, InspectionCheck]) -> List[Benchmark]:
        def from_file(path: str) -> Benchmark:
            with open(path, "rt", encoding="utf-8") as f:
                js = json.load(f)
                return from_json(js, Benchmark)

        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../inspect/benchmark")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for path in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                benchmark = from_file(path)
                if benchmark.is_valid(inspections):
                    result.append(benchmark)
                else:
                    log.warning(f"Invalid benchmark {benchmark.title} in {path}")
        return result


class Inspector(ABC):
    @abstractmethod
    async def get(self, uid: str) -> Optional[InspectionCheck]:
        pass

    @abstractmethod
    async def list(
        self,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        category: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> List[InspectionCheck]:
        pass

    @abstractmethod
    async def update(self, inspection: InspectionCheck) -> InspectionCheck:
        pass

    @abstractmethod
    async def delete(self, uid: str) -> None:
        pass
