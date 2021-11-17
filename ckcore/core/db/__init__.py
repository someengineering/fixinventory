from dataclasses import dataclass
from datetime import datetime


@dataclass
class SystemData:
    system_id: str
    created_at: datetime
    db_version: int
