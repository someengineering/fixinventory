![Fix Shell](https://cdn.fix.security/assets/fixinventory/fixinventory-search-multiple.gif)

[![Version](https://img.shields.io/github/v/tag/someengineering/fixinventory?label=latest)](https://github.com/someengineering/fixinventory/tags/)
[![Build](https://img.shields.io/github/actions/workflow/status/someengineering/fixinventory/docker-build.yml)](https://github.com/someengineering/fixinventory/commits/main)
[![Docs](https://img.shields.io/badge/docs-latest-<COLOR>.svg)](https://inventory.fix.security/docs)
[![Discord](https://img.shields.io/discord/778029408132923432?label=discord)](https://discord.gg/fixsecurity)
[![Known Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/someengineering/fixinventory/requirements.txt)](https://app.snyk.io/org/some-engineering-inc./projects)
[![CodeCoverage](https://codecov.io/gh/someengineering/fixinventory/graph/badge.svg?token=ZEZW5JAR5J)](https://codecov.io/gh/someengineering/fixinventory)

Fix Inventory detects compliance and security risks in cloud infrastructure accounts. 

We biult Fix Inventory for cloud and security enginers as an open source alternative to proprietary cloud security tools like Orca Security, Prisma Cloud or Wiz.

Check out our [Quick Start Guide](https://inventory.fix.security/docs/getting-started/) for step-by-step instructions on getting started. 

## 💡Why Fix Inventory?

Fix Inventory was built from the ground up for cloud-native infrastructure. Fix Inventory is open source and supports over 300 cloud services across:

- [Amazon Web Services (AWS)](https://github.com/someengineering/fixinventory/blob/main/plugins/aws)
- [Google Cloud Platform (GCP)](https://github.com/someengineering/fixinventory/blob/main/plugins/gcp)
- [Microsoft Azure](https://github.com/someengineering/fixinventory/tree/main/plugins/azure)
- [DigitalOcean](https://github.com/someengineering/fixinventory/blob/main/plugins/digitalocean)
- [Hetzner](https://github.com/someengineering/fixinventory/tree/main/plugins/hetzner)
- [Kubernetes (K8)](https://github.com/someengineering/fixinventory/tree/main/plugins/k8s)
- [GitHub](https://github.com/someengineering/fixinventory/tree/main/plugins/github)

If you want to collect data for resources that are not supported yet,  you can use our [example collector](https://github.com/someengineering/fixinventory/tree/main/plugins/example_collector) to write your own collectors.

The tool works in three phases: 

1. **Collect inventory data**: Fix Inventory queries cloud infrastructure APIs (aka “agentless”) for metadata about the resources in your cloud accounts.
   
2. **Normalize cloud data**: Fix Inventory creates a graph schema to normalize the universe of detected cloud resources, their configurations, and relationships.
    
3. **Triage security risks**: Fix Inventory scans the collected data with custom and pre-configured compliance frameworks to search for misconfigurations, risks, and other security issues.

Fix Inventory also provides ways to export and integrate the data it collects to build alerting and remediation workflows.

## 🍀 How is Fix Inventory different?

In cloud-native infrastructure, misconfigurations from developer activity and frequent updates through automation are a fact of life. It's impossible to catch all misconfigurations before they reach production, so the key question becomes: how quickly can you identify and fix (hence the name…) the most critical risks?

Traditional cloud security tools struggle to answer basic questions such as “what’s the blast radius of this public resource?” or “is there a path to get from this resource to a privileged role?”, because they lack the context from the hidden dependencies between cloud resources. 

We believe that the only effective approach is to use a graph-based data model that works across all cloud platforms. 

- **Deploy anywhere:** Fix Inventory can be deployed on your laptop or in the cloud, and we also offer a SaaS version.

- **High performing**: Fix Inventory scales across thousands of cloud accounts, is optimized for performance, and collects data in parallel while being mindful of cloud provider API quotas.

- **Dependency and access graph**: Fix Inventory stores dependency and access metadata in a graph database and makes it queryable for users. For risk analysis, you can traverse the graph and weave together interconnected risks in a fraction of a second.

- **Multi-cloud abstractions**: Our unified data model uses over 40 “[base kinds](https://inventory.fix.security/reference/unified-data-model/base-kinds)” to describe common resources such as ‘database’ or ‘ip_address’, to implement a single set of policies (e.g. “no unencrypted storage volumes”) that works across all clouds.

- **Resource lifecycle tracking:** By default, Fix takes an hourly snapshot of your inventory and tracks configuration changes for each resource. Each snapshot is stored, which creates a timeline and diff view for every resource and its changes.

## 🛠️ Use cases

Fix Inventory supports common cloud security use cases.

- **Cloud Security Posture Management (CSPM)**: Monitor and enforce security policies across your cloud infrastructure, Identify and remediate misconfigurations.
  
- **AI Security Posture Management (AI-SPM)**: Automatic discovery of AI services in use, and the data sources they connect to.
  
- **Cloud Compliance**: Run automated compliance assessments across your cloud accounts with standard compliance frameworks.
  
- **Cloud Infrastructure Entitlement Management (CIEM)**: Discover human and non-human identities (NHI), detect risky service accounts with access to sensitive data.

- **Cloud Asset Inventory:** Gain visibility into your multi-cloud environments by collecting, normalizing, unifying resource configuration data and prevent shadow IT
  
- **Container & Kubernetes Security**: Get complete visibility, from individual containers and Kubernetes objects to namespaces, nodes, clusters, and the underlying cloud infrastructure.
  
- **Security Data Fabric**: Integrate security data from multiple cloud providers into a single place and export data for usage in other systems and databases.
  
- **Policy-as-code:** Script and apply policies across your multi-cloud infrastructure and establish best practices for reliability, cost control, and resource configurations. 

Please also see [Fix Security](https://fix.security/), our hosted SaaS offering that is built on top of Fix Inventory.

## 🏄 Key concepts

Three concepts are helpful to understand how Fix Inventory works and how it’s different from other cloud security tools.

### 1. Normalized cloud data

Fix Inventory has knowledge of the provider-specific data model for every resource. To collect metadata from every cloud, Fix Inventory uses a pluggable architecture. Each collector plugin includes logic to extract data from the cloud provider APIs. 

Post-collection, Fix Inventory normalizes the data and maps it to our [unified data model](https://inventory.fix.security/reference/unified-data-model) with [common properties](https://inventory.fix.security/reference/unified-data-model#resource-base-kind), [static typing](https://inventory.fix.security/reference/unified-data-model#complex-and-simple-kinds) and [inheritance](https://inventory.fix.security/reference/unified-data-model#resource-hierarchy). 

In Fix Inventory, everything is a `resource` - cloud services, users, policies, etc. 

- `id`, `name`, `kind`, `tags`, `age`, `last_access`, `last_update` are normalized resource properties
- `cloud`, `account`, and `region` data denote the location of each resource.

The mapping with common properties, static typing and inheritance allow you to interact with resources across cloud providers in a consistent fashion. 

For example, resource time stamps in Fix Inventory are normalized, which allows the use of relative times. Assume we want to find resources created in the last 3 days, no matter which cloud. Then we could express this with a relative duration string:

```jsx
search age < "3d”
```

### 2. Query language & policies

Fix Inventory comes with a human-readable query language, and the user interface is our [CLI](https://inventory.fix.security/reference/cli). The CLI provides an easy way to explore your infrastructure and get answers to security-related questions such as:

- Does user X have privileged access to resource Y?

- What resources are behind public IP address X?

- Which resources are incorrectly tagged?

Due to its statically typed data model, you can search for names, strings, or numbers in any combination. You can also leverage the dependency and access graph to include the relationships between resources, users, and permissions in your searches. Fix Inventory also supports [full-text search](https://inventory.fix.security/reference/search/full-text). 

One key purpose of our query language is to define rules and policies that govern how your infrastructure should behave and then automatically trigger alerts and actions when these rules are violated.

For example, if you have a policy that all volumes must be encrypted, the following search will return all unencrypted volumes:

```python
> search is(volume) and volume_encrypted=false
```

The search leverages the common kind `volume` and will return results for all clouds. Turning a search into a policy and setting up [alerting](https://inventory.fix.security/how-to-guides/alerting) is also possible.

Fix Inventory ships with industry-standard benchmarks, like the CIS Benchmarks for AWS or Azure, the ISO-27001 or NIS-2. A report can be generated by invoking the [report](https://inventory.fix.security/reference/cli/report/benchmark) command:

```jsx
> report benchmark run iso27001
```

### Dependency and access graph

Fix Inventory stores relationships between resources in your cloud environment to understand logical dependencies and detect hidden pathways to potential breaches. You can: 

- Query complex relationships across cloud layers.
  
- Add context by filtering for resource properties.
  
- Visualize search outputs to make risks more understandable.

For example, suppose I want to understand which S3 buckets in my infrastructure a user “Matthias” has write access to. In that case, I can write a query that uses the IAM (identity access management) graph to find out.  I can pipe the search results into a [DOT file](https://en.wikipedia.org/wiki/DOT_(graph_description_language)) and create a visualization that explains relationships to people without cloud or security expertise. 

```bash
 > search --with-edges is(aws_iam_user) and name=matthias -iam[0:]{permissions[*].level==write}-> is(aws_iam_user, aws_s3_bucket) | format --dot
```

![Fix Graph](https://cdn.fix.security/assets/fixinventory/fixinventory-security-graph.png)

Read more about [traversing the graph](https://inventory.fix.security/concepts/asset-inventory-graph#traversal) in our docs. Fix Security, our hosted SaaS product, offers these visualizations out of the box.

## 💖 Community

Fix Inventory is an open-source project by Some Engineering. Contact us on [our Discord server](https://discord.gg/fixsecurity) for:

- help with getting started
  
- issues you encounter
  
- writing queries
  
- using the dependency and access graph

## 🙏 Contributing

Feel free to [open a GitHub issue](https://github.com/someengineering/fixinventory/issues/new) for small fixes and changes. For bigger changes and new plugins, please open an issue first to prevent duplicated work and to have the relevant discussions first. 

Please follow our [contribution guidelines](https://inventory.fix.security/development) to get started.

## 🎟 License

See [LICENSE](LICENSE) for details.
