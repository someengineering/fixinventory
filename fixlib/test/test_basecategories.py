from attrs import define
from typing import ClassVar, List
from fixlib.basecategories import (
    BaseCategory,
    Compute,
    Storage,
    Database,
    Security,
    Networking,
    Iam,
    Management,
    Monitoring,
    Analytics,
    Ai,
    DevOps,
)


def test_base_category_empty():
    class EmptyCategory(BaseCategory):
        pass

    assert EmptyCategory.get_all_categories() == []
    assert EmptyCategory().categories == []


def test_single_category():
    assert Compute.get_all_categories() == ["compute"]
    assert Compute().categories == ["compute"]

    assert Storage.get_all_categories() == ["storage"]
    assert Storage().categories == ["storage"]


def test_multiple_categories():
    @define(eq=False, slots=False)
    class CustomCategory(Compute, Storage):
        _categories: ClassVar[List[str]] = ["custom"]

    expected_categories = ["compute", "storage", "custom"]
    assert set(CustomCategory.get_all_categories()) == set(expected_categories)
    assert set(CustomCategory().categories) == set(expected_categories)


def test_deeply_nested_categories():
    @define(eq=False, slots=False)
    class CustomCategory1(Compute):
        _categories: ClassVar[List[str]] = ["custom1"]

    @define(eq=False, slots=False)
    class CustomCategory2(CustomCategory1, Storage):
        _categories: ClassVar[List[str]] = ["custom2"]

    expected_categories = ["compute", "custom1", "storage", "custom2"]
    assert set(CustomCategory2.get_all_categories()) == set(expected_categories)
    assert set(CustomCategory2().categories) == set(expected_categories)


def test_all_categories():
    classes = [Compute, Storage, Database, Security, Networking, Iam, Management, Monitoring, Analytics, Ai, DevOps]

    for cls in classes:
        assert cls.get_all_categories() == cls._categories
        assert cls().categories == cls._categories
