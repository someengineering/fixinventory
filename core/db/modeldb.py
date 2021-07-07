import logging
from abc import ABC, abstractmethod
from typing import List, AsyncGenerator, Dict

from arango.collection import StandardCollection

from core.db.async_arangodb import AsyncArangoDB
from core.event_bus import EventBus, Event
from core.model.model import Kind
from core.model.typed_model import from_js, to_js

log = logging.getLogger(__name__)


class ModelDB(ABC):
    @abstractmethod
    def get_kinds(self) -> AsyncGenerator[Kind, None]:
        pass

    @abstractmethod
    async def update_kinds(self, model: List[Kind]) -> None:
        pass

    @abstractmethod
    async def delete_kind(self, model: Kind) -> None:
        pass


class ArangoModelDB(ModelDB):
    def __init__(self, db: AsyncArangoDB, model: str):
        self.db = db
        self.model = model

    async def get_kinds(self) -> AsyncGenerator[Kind, None]:  # pylint: disable=invalid-overridden-method
        with await self.db.all(self.model) as cursor:
            for kind in cursor:
                yield from_js(kind, Kind)  # type: ignore

    async def update_kinds(self, model: List[Kind]) -> None:
        await self.db.insert_many(self.model, [self.__to_doc(kind) for kind in model], overwrite=True)

    async def delete_kind(self, model: Kind) -> None:
        await self.db.delete(self.model, self.__to_doc(model))

    async def create_update_schema(self) -> StandardCollection:
        name = self.model
        db = self.db
        return db.collection(name) if await db.has_collection(name) else await db.create_collection(name)

    async def wipe(self) -> bool:
        return await self.db.truncate(self.model)

    @staticmethod
    def __to_doc(kind: Kind) -> Dict[str, object]:
        js = to_js(kind)
        js["_key"] = kind.fqn
        return js


class EventModelDB(ModelDB):
    def __init__(self, db: ModelDB, event_bus: EventBus):
        self.db = db
        self.event_bus = event_bus

    def get_kinds(self) -> AsyncGenerator[Kind, None]:
        return self.db.get_kinds()

    async def update_kinds(self, model: List[Kind]) -> None:
        result = await self.db.update_kinds(model)
        await self.event_bus.emit(Event.ModelUpdated, {"updated": [to_js(kind) for kind in model]})
        return result

    async def delete_kind(self, model: Kind) -> None:
        result = await self.db.delete_kind(model)
        await self.event_bus.emit(Event.ModelDeleted, to_js(model))
        return result
