from conftest import roundtrip_check
from fix_plugin_azure.resource.base import GraphBuilder
from fix_plugin_azure.resource.web import (
    AzureWebAppServicePlan,
    AzureWebApp,
    AzureWebAppStaticSite,
    AzureWebCertificate,
    AzureWebContainerApp,
    AzureWebDomain,
    AzureWebHostingEnvironment,
    AzureWebKubeEnvironment,
)


def test_app_service_plan(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebAppServicePlan, builder)
    assert len(collected) == 2


def test_web_app(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebApp, builder)
    assert len(collected) == 2
    collected[0].post_process(builder, {})
    builder.executor.wait_for_submitted_work()
    assert collected[0].app_authentication_settings is not None


def test_app_static_site(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebAppStaticSite, builder)
    assert len(collected) == 1


def test_app_certificate(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebCertificate, builder)
    assert len(collected) == 2


def test_app_container_app(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebContainerApp, builder)
    assert len(collected) == 1


def test_app_domain(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebDomain, builder)
    assert len(collected) == 1


def test_app_hosting_environment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebHostingEnvironment, builder)
    assert len(collected) == 1


def test_app_kube_environment(builder: GraphBuilder) -> None:
    collected = roundtrip_check(AzureWebKubeEnvironment, builder)
    assert len(collected) == 2
