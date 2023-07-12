from abc import ABC
from typing import Any, TypeVar

ServiceType = TypeVar("ServiceType", bound="Service")


class Service(ABC):
    async def start(self) -> Any:
        pass

    async def stop(self) -> None:
        pass

    async def __aenter__(self: ServiceType) -> ServiceType:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()
