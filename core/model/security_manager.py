from __future__ import annotations
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Generator

local = threading.local()


class SecurityManager(ABC):

    @abstractmethod
    def allowed_to_view(self, clazz: type, prop: Any) -> bool:
        pass

    @staticmethod
    def get() -> Any:
        return getattr(local, "security_manager")

    @staticmethod
    @contextmanager
    def use(manager: SecurityManager) -> Generator[SecurityManager, None, None]:
        setattr(local, "security_manager", manager)
        yield manager
        setattr(local, "security_manager", None)


class NoSensitiveData(SecurityManager):
    """
    Dummy implementation to test
    """
    def allowed_to_view(self, clazz: type, prop: Any) -> bool:
        return not prop.sensitive
