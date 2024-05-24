from abc import ABC
from attrs import define
from typing import ClassVar, List, Type


@define(eq=False, slots=False)
class BaseCategory(ABC):
    kind: ClassVar[str] = "category"
    _categories: ClassVar[List[str]] = []

    @classmethod
    def get_all_categories(cls: Type["BaseCategory"]) -> List[str]:
        def gather_categories(class_type: Type["BaseCategory"]) -> List[str]:
            merged = []
            for base in class_type.__bases__:
                if issubclass(base, BaseCategory):
                    merged.extend(gather_categories(base))
            if hasattr(class_type, "_categories"):
                merged.extend(class_type._categories)
            return merged

        return list(set(gather_categories(cls)))

    @property
    def categories(self) -> List[str]:
        return self.get_all_categories()


@define(eq=False, slots=False)
class Compute(BaseCategory):
    _categories: ClassVar[List[str]] = ["compute"]


@define(eq=False, slots=False)
class Storage(BaseCategory):
    _categories: ClassVar[List[str]] = ["storage"]


@define(eq=False, slots=False)
class Database(BaseCategory):
    _categories: ClassVar[List[str]] = ["database"]


@define(eq=False, slots=False)
class Security(BaseCategory):
    _categories: ClassVar[List[str]] = ["security"]


@define(eq=False, slots=False)
class Networking(BaseCategory):
    _categories: ClassVar[List[str]] = ["networking"]


@define(eq=False, slots=False)
class Iam(BaseCategory):
    _categories: ClassVar[List[str]] = ["iam"]


@define(eq=False, slots=False)
class Management(BaseCategory):
    _categories: ClassVar[List[str]] = ["management"]


@define(eq=False, slots=False)
class Monitoring(BaseCategory):
    _categories: ClassVar[List[str]] = ["monitoring"]


@define(eq=False, slots=False)
class Analytics(BaseCategory):
    _categories: ClassVar[List[str]] = ["analytics"]


@define(eq=False, slots=False)
class Ai(BaseCategory):
    _categories: ClassVar[List[str]] = ["ai"]


@define(eq=False, slots=False)
class DevOps(BaseCategory):
    _categories: ClassVar[List[str]] = ["devops"]
