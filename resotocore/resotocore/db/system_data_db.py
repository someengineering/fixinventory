from typing import Tuple, Dict, Optional

from resotocore.db import SystemData, drop_arango_props
from resotocore.db.async_arangodb import AsyncArangoDB
from resotocore.model.typed_model import from_js
from resotocore.util import if_set


class SystemDataDb:
    def __init__(self, db: AsyncArangoDB):
        self.db = db
        self.collection_name = "system_data"

    async def system_data(self) -> SystemData:
        return if_set(await self.db.get(self.collection_name, "system"), lambda x: from_js(x, SystemData))  # type: ignore # noqa E501

    async def ca(self) -> Tuple[str, str]:
        return if_set(await self.db.get(self.collection_name, "ca"), lambda x: (x["key"], x["certificate"]))  # type: ignore # noqa E501

    async def jwt_signing_keys(self) -> Optional[Tuple[str, str]]:
        return if_set(await self.db.get(self.collection_name, "jwt_signing_keys"), lambda x: (x["key"], x["certificate"]))  # type: ignore # noqa E501

    async def info(self) -> Dict[str, str]:
        return drop_arango_props((await self.db.get(self.collection_name, "info")) or {})

    async def update_jwt_signing_keys(self, key: str, certificate: str) -> Tuple[str, str]:
        doc = await self.db.insert(
            self.collection_name,
            {"_key": "jwt_signing_keys", "key": key, "certificate": certificate},
            return_new=True,
            overwrite=True,
            overwrite_mode="replace",
        )
        return doc["new"]["key"], doc["new"]["certificate"]  # type: ignore

    async def update_info(self, **kwargs: str) -> Dict[str, str]:
        kwargs["_key"] = "info"
        doc = await self.db.insert(
            self.collection_name, kwargs, return_new=True, overwrite=True, overwrite_mode="update", merge=True
        )
        return drop_arango_props(doc["new"])  # type: ignore
