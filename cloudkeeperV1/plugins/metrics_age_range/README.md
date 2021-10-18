# cloudkeeper-plugin-metrics_age_range
Age Range Metrics Plugin for Cloudkeeper

This plugin adds additional resource age metrics.

## Usage
```
$ cloudkeeper -v --metrics-age-range
```

### Example
The Prometheus `/metrics` endpoint will have additional metrics for instance and volume resources grouping them by age.

```
cloudkeeper_instances_age_range{account="327650738955",age="12h",cloud="aws",region="us-west-2",status="running",type="t3.xlarge"} 10.0
cloudkeeper_instances_age_range{account="327650738955",age="12h",cloud="aws",region="us-west-2",status="running",type="m5.xlarge"} 3.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="running",type="t3.xlarge"} 24.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="terminated",type="t3.xlarge"} 24.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="terminated",type="m5.xlarge"} 22.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="running",type="m5.xlarge"} 17.0
cloudkeeper_instances_age_range{account="327650738955",age="1h",cloud="aws",region="us-west-2",status="running",type="t3.xlarge"} 10.0
cloudkeeper_instances_age_range{account="327650738955",age="1h",cloud="aws",region="us-west-2",status="running",type="m5.xlarge"} 5.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="terminated",type="t3.large"} 3.0
cloudkeeper_instances_age_range{account="327650738955",age="2h",cloud="aws",region="us-west-2",status="running",type="m5.2xlarge"} 4.0
cloudkeeper_instances_age_range{account="327650738955",age="1h",cloud="aws",region="us-west-2",status="running",type="m5.2xlarge"} 6.0
cloudkeeper_instances_age_range{account="327650738955",age="1h",cloud="aws",region="us-west-2",status="running",type="p2.xlarge"} 4.0
```

## List of age ranges:

| `age` label | Range |
| --- | --- |
| `1h` | 0s to 1h |
| `2h` | 1h to 2h |
| `4h` | 2h to 4h |
| `8h` | 4h to 8h |
| `12h` | 8h to 12h |
| `1d` | 12h to 1d |
| `7d` | 1d to 7d |
| `30d` | 7d to 30d |

## List of arguments
```
  --metrics-age-range   Metrics: Age Range (default: False)
```
