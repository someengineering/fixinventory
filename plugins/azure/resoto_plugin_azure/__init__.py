import logging
from typing import Optional, ClassVar

from attr import define, field

from resotolib.baseplugin import BaseCollectorPlugin
from resotolib.config import Config
from resotolib.core.actions import CoreFeedback

log = logging.getLogger("resoto.plugin.azure")


class AzureCollectorPlugin(BaseCollectorPlugin):
    cloud = "azure"

    def __init__(self) -> None:
        super().__init__()
        self.core_feedback: Optional[CoreFeedback] = None

    @staticmethod
    def add_config(cfg: Config) -> None:
        cfg.add_config(AzureConfig)

    @staticmethod
    def auto_enableable() -> bool:
        return False

    def collect(self) -> None:
        # TODO: implement me
        pass


@define(slots=False)
class AzureConfig:
    kind: ClassVar[str] = "azure"

    resource_pool_size: int = field(
        default=10, metadata={"description": "Number of threads to use for resource collection"}
    )
