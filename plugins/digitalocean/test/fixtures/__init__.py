# flake8: noqa F401
from .droplets import droplets as droplets
from .regions import regions as regions
from .volumes import volumes as volumes
from .vpcs import vpcs as vpcs
from .databases import databases as databases
from .k8s import k8s as k8s
from .snapshots import snapshots as snapshots
from .loadbalancers import load_balancers as load_balancers
from .floatingip import floating_ips as floating_ips
from .projects import projects as projects
from .projectresources import project_resources as project_resources
from .spaces import spaces as spaces
from .apps import apps as apps
from .cdns import cdn_endpoints as cdn_endpoints
from .certificates import certificates as certificates
from .registry import registry as registry
from .registry_repositories import registry_repositories as registry_repositories
from .registry_repository_tags import (
    registry_repository_tags as registry_repository_tags,
)
from .ssh_keys import ssh_keys as ssh_keys
from .tags import tags as tags
from .domains import domains as domains
from .domain_records import domain_records as domain_records
from .firewalls import firewalls as firewalls
from .alerts import alerts as alerts
