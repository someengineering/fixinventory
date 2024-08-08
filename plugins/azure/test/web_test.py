from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.web import (
    AzureAppServicePlan,
    AzureWebApp,
    AzureAppStaticSite,
    AzureCertificate,
    AzureContainerApp,
    AzureDomain,
    AzureHostingEnvironment,
    AzureKubeEnvironment,
)


def test_app_service_plan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAppServicePlan, builder)
    assert len(collected) == 2


def test_web_app(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebApp, builder)
    assert len(collected) == 2
    collected[0].post_process(builder, {})
    builder.executor.wait_for_submitted_work()
    assert collected[0].app_authentication_settings is not None


def test_app_static_site(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureAppStaticSite, builder)
    assert len(collected) == 1


def test_app_certificate(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureCertificate, builder)
    assert len(collected) == 2


def test_app_container_app(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureContainerApp, builder)
    assert len(collected) == 1


def test_app_domain(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureDomain, builder)
    assert len(collected) == 1


def test_app_hosting_environment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureHostingEnvironment, builder)
    assert len(collected) == 1


def test_app_kube_environment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureKubeEnvironment, builder)
    assert len(collected) == 2
