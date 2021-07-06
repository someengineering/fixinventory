import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager

local = threading.local()


class SecurityManager(ABC):

    @abstractmethod
    def allowed_to_view(self, clazz: type, prop) -> bool:
        pass

    @staticmethod
    def get():
        return getattr(local, "security_manager")

    @staticmethod
    @contextmanager
    def use(manager):
        setattr(local, "security_manager", manager)
        yield manager
        setattr(local, "security_manager", None)


class NoSensitiveData(SecurityManager):
    """
    Dummy implementation to test
    """
    def allowed_to_view(self, clazz: type, prop) -> bool:
        return not prop.sensitive
