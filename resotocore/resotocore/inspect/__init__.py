from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict

from attr import define, field

from resotocore.types import Json


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
    categories: List[str]
    severity: InspectionSeverity
    detect: Dict[str, str]
    remediation: Remediation
    url: Optional[str] = None
    related: List[str] = field(factory=list)

    @staticmethod
    def from_file(path: str) -> List[InspectionCheck]:
        def inspection(provider: str, service: str, check: Json) -> InspectionCheck:
            return InspectionCheck(
                id=f'{provider}_{service}_{check["name"]}',
                provider=provider,
                service=service,
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

        with open(path, "rt", encoding="utf-8") as f:
            js = json.load(f)
            pdr = js["provider"]
            svc = js["service"]
            return [inspection(pdr, svc, check) for check in js["checks"]]

    @staticmethod
    def from_files() -> List[InspectionCheck]:
        # TODO: define final path and add to Manifest
        static_path = os.path.abspath(os.path.dirname(__file__) + "/../../../inspect/checks/provider")
        result = []
        for provider in (d.path for d in os.scandir(static_path) if d.is_dir()):
            for service in (d.path for d in os.scandir(provider) if d.is_file() and d.name.endswith(".json")):
                result.extend(InspectionCheck.from_file(service))
        return result


class Inspector(ABC):
    @abstractmethod
    async def get(self, uid: str) -> Optional[InspectionCheck]:
        pass

    @abstractmethod
    async def list(
        self, provider: Optional[str] = None, service: Optional[str] = None, category: Optional[str] = None
    ) -> List[InspectionCheck]:
        pass

    @abstractmethod
    async def update(self, inspection: InspectionCheck) -> InspectionCheck:
        pass

    @abstractmethod
    async def delete(self, uid: str) -> None:
        pass
