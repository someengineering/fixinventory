<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="/misc/fixinventory_200-darkmode.png"><source media="(prefers-color-scheme: light)" srcset="/misc/fixinventory_200-lightmode.png"><img alt="Fix Inventory" src="/misc/fixinventory_200-lightmode.png"></picture></p>

<p align="center"><img src="/misc/fixinventory_banner.png"/></p>

[![Version](https://img.shields.io/github/v/tag/someengineering/fixinventory?label=latest)](https://github.com/someengineering/fixinventory/tags/)
[![Build](https://img.shields.io/github/actions/workflow/status/someengineering/fixinventory/docker-build.yml)](https://github.com/someengineering/fixinventory/commits/main)
[![Docs](https://img.shields.io/badge/docs-latest-<COLOR>.svg)](https://inventory.fix.security/docs)
[![Discord](https://img.shields.io/discord/778029408132923432?label=discord)](https://discord.gg/fixsecurity)
[![Known Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/someengineering/fixinventory/requirements.txt)](https://app.snyk.io/org/some-engineering-inc./projects)
[![CodeCoverage](https://codecov.io/gh/someengineering/fixinventory/graph/badge.svg?token=ZEZW5JAR5J)](https://codecov.io/gh/someengineering/fixinventory)

## Table of contents

* [Overview](#overview)
* [Getting started](#getting-started)
* [Component list](#component-list)
* [Contact](#contact)
* [License](#license)


## Overview
🔍 Search Infrastructure: Fix Inventory maps out your cloud infrastructure in a [graph](https://inventory.fix.security/concepts/asset-inventory-graph) and provides a simple [search syntax](https://inventory.fix.security/docs/concepts/search).

📊 Generate Reports: Fix Inventory keeps track of and reports infrastructure changes over time, making it easy to [audit resource usage and cleanup](https://inventory.fix.security/docs/concepts/cloud-data-sync).

🤖 Automate Tasks: Tedious tasks like rule enforcement, resource tagging, and cleanup can be [automated using jobs](https://inventory.fix.security/docs/concepts/automation).

Currently, Fix Inventory can collect [AWS](plugins/aws), [Google Cloud](plugins/gcp), [DigitalOcean](plugins/digitalocean), [VMWare Vsphere](plugins/vsphere), [OneLogin](plugins/onelogin), and [Slack](plugins/slack) resources. If the cloud you are using is not listed, it is easy to write your own collectors. An example can be found [here](plugins/example_collector).

## Getting started

Continue reading [the Quick Start Guide](https://inventory.fix.security/docs/getting-started/)


# Component list
- [`fixcore`](fixcore) the platform maintaining the [MultiDiGraph](https://en.wikipedia.org/wiki/Multigraph#Directed_multigraph_(edges_with_own_identity)).
- [`fixshell`](fixshell) the Fix Inventory shell to interact with the core.
- [`fixworker`](fixworker) provides workers that load [plugins](plugins) to perform collect and cleanup operations.
- [`fixmetrics`](fixmetrics) is a [Prometheus](https://prometheus.io/) [exporter](https://prometheus.io/docs/instrumenting/exporters/).
- [`plugins`](plugins) are a collection of worker plugins like [AWS](plugins/aws)


## Contact
If you have any questions, feel free to [join our Discord](https://discord.gg/fixsecurity) or [open a GitHub issue](https://github.com/someengineering/fixinventory/issues/new).


## License
See [LICENSE](LICENSE) for details.
