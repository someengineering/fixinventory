from fixlib.basecategories import Category
from fixlib.baseresources import (
    BaseResource,
    BaseInstance,
    BaseVolume,
    BaseNetwork,
    BaseDatabase,
    BaseFirewall,
    BaseLoadBalancer,
    BaseUser,
    BaseGroup,
    BasePolicy,
    BaseRole,
    BaseKeyPair,
    BaseSnapshot,
    BaseHealthCheck,
    BaseDNSZone,
    BaseDNSRecordSet,
    BaseAutoScalingGroup,
)


def test_base_category_empty():
    class EmptyCategory(BaseResource):
        pass

    assert EmptyCategory.get_all_categories() == []


def test_single_category():
    assert BaseInstance.get_all_categories() == [Category.compute]
    assert BaseInstance(id="instance").categories() == ["compute"]

    assert BaseVolume.get_all_categories() == [Category.storage]
    assert BaseVolume(id="volume").categories() == ["storage"]


def test_multiple_categories():
    class CustomResource(BaseInstance, BaseVolume):
        _categories = [Category.management]

    expected_categories = [Category.compute, Category.storage, Category.management]
    expected_categories_str = [str(category.value) for category in expected_categories]
    assert set(CustomResource.get_all_categories()) == set(expected_categories)
    assert sorted(CustomResource(id="custom_resource").categories()) == sorted(expected_categories_str)


def test_deeply_nested_categories():
    class CustomResource1(BaseInstance):
        _categories = [Category.monitoring]

    class CustomResource2(CustomResource1, BaseVolume):
        _categories = [Category.security]

    expected_categories = [Category.compute, Category.monitoring, Category.storage, Category.security]
    expected_categories_str = [str(category.value) for category in expected_categories]
    assert set(CustomResource2.get_all_categories()) == set(expected_categories)
    assert sorted(CustomResource2(id="custom_resource2").categories()) == sorted(expected_categories_str)


def test_all_categories():
    expected_categories = {
        BaseInstance: [Category.compute],
        BaseVolume: [Category.storage],
        BaseNetwork: [Category.networking],
        BaseDatabase: [Category.compute, Category.database],
        BaseFirewall: [Category.networking, Category.security],
        BaseLoadBalancer: [Category.networking],
        BaseUser: [Category.access_control],
        BaseGroup: [Category.access_control],
        BasePolicy: [Category.access_control],
        BaseRole: [Category.access_control],
        BaseKeyPair: [Category.access_control],
        BaseSnapshot: [Category.storage],
        BaseHealthCheck: [Category.monitoring],
        BaseDNSZone: [Category.dns, Category.networking],
        BaseDNSRecordSet: [Category.dns],
        BaseAutoScalingGroup: [Category.compute, Category.management],
    }

    for resource_class, expected_categories_list in expected_categories.items():
        assert set(resource_class.get_all_categories()) == set(expected_categories_list)
