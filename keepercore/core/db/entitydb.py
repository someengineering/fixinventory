import logging
from abc import ABC, abstractmethod
from typing import List, AsyncGenerator, Generic, TypeVar, Optional, Type, Union, Callable

from core.db.async_arangodb import AsyncArangoDB
from core.event_bus import EventBus
from core.model.typed_model import from_js, to_js
from core.types import Json

log = logging.getLogger(__name__)

T = TypeVar("T")


class EntityDb(ABC, Generic[T]):
    @abstractmethod
    async def all(self) -> AsyncGenerator[T, None]:
        yield None  # type: ignore

    @abstractmethod
    async def update_many(self, elements: List[T]) -> None:
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[T]:
        pass

    @abstractmethod
    async def update(self, t: T) -> T:
        pass

    @abstractmethod
    async def delete(self, key_or_object: Union[str, T]) -> None:
        pass

    @abstractmethod
    async def create_update_schema(self) -> None:
        pass


class ArangoEntityDb(EntityDb[T], ABC):
    def __init__(self, db: AsyncArangoDB, collection_name: str, t_type: Type[T], key_fn: Callable[[T], str]):
        self.db = db
        self.collection_name = collection_name
        self.t_type = t_type
        self.key_of = key_fn

    async def all(self) -> AsyncGenerator[T, None]:
        with await self.db.all(self.collection_name) as cursor:
            for element in cursor:
                yield from_js(element, self.t_type)

    async def update_many(self, elements: List[T]) -> None:
        await self.db.insert_many(self.collection_name, [self.__to_doc(kind) for kind in elements], overwrite=True)

    async def get(self, key: str) -> Optional[T]:
        result = await self.db.get(self.collection_name, key)
        return from_js(result, self.t_type) if result else None

    async def update(self, t: T) -> T:
        await self.db.insert(self.collection_name, self.__to_doc(t), overwrite=True)
        return t

    async def delete(self, key_or_object: Union[str, T]) -> None:
        key = key_or_object if isinstance(key_or_object, str) else self.key_of(key_or_object)
        await self.db.delete(self.collection_name, key)

    async def create_update_schema(self) -> None:
        name = self.collection_name
        db = self.db
        if not await db.has_collection(name):
            await db.create_collection(name)

    async def wipe(self) -> bool:
        return await self.db.truncate(self.collection_name)

    def __to_doc(self, t: T) -> Json:
        js = to_js(t)
        js["_key"] = self.key_of(t)
        return js


class EventEntityDb(EntityDb[T]):
    def __init__(self, db: EntityDb[T], event_bus: EventBus, entity_name: str):
        self.db = db
        self.event_bus = event_bus
        self.entity_name = entity_name

    async def all(self) -> AsyncGenerator[T, None]:
        async for a in self.db.all():
            yield a

    async def update_many(self, elements: List[T]) -> None:
        result = await self.db.update_many(elements)
        await self.event_bus.emit_event(f"{self.entity_name}-updated-many", {"updated": [to_js(e) for e in elements]})
        return result

    async def get(self, key: str) -> Optional[T]:
        return await self.db.get(key)

    async def update(self, t: T) -> T:
        result = await self.db.update(t)
        await self.event_bus.emit_event(f"{self.entity_name}-updated", {"updated": to_js(result)})
        return result

    async def delete(self, key_or_object: Union[str, T]) -> None:
        await self.db.delete(key_or_object)
        await self.event_bus.emit_event(f"{self.entity_name}-deleted", {"deleted": to_js(key_or_object)})

    async def create_update_schema(self) -> None:
        return await self.db.create_update_schema()
