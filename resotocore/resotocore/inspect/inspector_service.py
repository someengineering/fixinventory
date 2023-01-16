from typing import Optional, List, Iterable

from resotocore.db.inspectiondb import InspectionCheckEntityDb
from resotocore.inspect import Inspector, InspectionCheck


class InspectorService(Inspector):
    def __init__(self, inspection_db: InspectionCheckEntityDb) -> None:
        self.inspection_db = inspection_db
        self.predefined_inspections = {i.id: i for i in InspectionCheck.from_files()}

    async def get(self, uid: str) -> Optional[InspectionCheck]:
        return (await self.inspection_db.get(uid)) or self.predefined_inspections.get(uid)

    async def list(
        self, provider: Optional[str] = None, service: Optional[str] = None, category: Optional[str] = None
    ) -> List[InspectionCheck]:
        result = {}

        def add_inspections(inspections: Iterable[InspectionCheck]) -> None:
            for inspection in inspections:
                if (
                    (provider is None or provider == inspection.provider)
                    and (service is None or service == inspection.service)
                    and (category is None or category in inspection.categories)
                ):
                    result[inspection.id] = inspection

        add_inspections(self.predefined_inspections.values())
        add_inspections([i async for i in self.inspection_db.all()])
        return list(result.values())

    async def update(self, inspection: InspectionCheck) -> InspectionCheck:
        return await self.inspection_db.update(inspection)

    async def delete(self, uid: str) -> None:
        result = await self.inspection_db.delete(uid)
        if not result and uid in self.predefined_inspections:
            raise ValueError(f"You can adjust predefined inspections, but not delete them: {uid}")
