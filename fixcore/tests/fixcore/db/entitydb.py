import asyncio
from typing import Optional, AsyncGenerator, Type, Callable, Dict, List, Generic

from fixcore.db.entitydb import EntityDb, T, K
from fixcore.model.typed_model import from_js, to_js
from fixcore.types import Json


# workaround to check generic types in runtime, aka type tags
class TypeTag(Generic[T]):
    def __init__(self, inner: T) -> None:
        self.inner = inner


class InMemoryDb(EntityDb[K, T]):
    def __init__(self, t_type: Type[T], key_fn: Callable[[T], K]):
        self.items: Dict[K, Json] = {}
        self.t_type = t_type
        self.key_fn = key_fn

    async def keys(self) -> AsyncGenerator[K, None]:
        for key in self.items:
            await asyncio.sleep(0)
            yield key

    async def all(self) -> AsyncGenerator[T, None]:
        for js in self.items.values():
            yield from_js(js, self.t_type)

    async def update_many(self, elements: List[T]) -> None:
        for elem in elements:
            key = self.key_fn(elem)
            self.items[key] = to_js(elem)

    async def get(self, key: K) -> Optional[T]:
        js = self.items.get(key)
        return from_js(js, self.t_type) if js else None

    async def update(self, t: T) -> T:
        self.items[self.key_fn(t)] = to_js(t)
        return t

    async def delete(self, key: K) -> bool:
        return self.items.pop(key, None) is not None

    async def delete_value(self, value: T) -> None:
        key = self.key_fn(value)
        self.items.pop(key, None)

    async def delete_many(self, keys: List[K]) -> None:
        for key in keys:
            self.items.pop(key, None)

    async def create_update_schema(self) -> None:
        pass

    async def wipe(self) -> bool:
        self.items = {}
        return True
