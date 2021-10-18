# cloudkeeper-plugin-report_cleanups
Cleanups Report plugin for Cloudkeeper

This plugin writes csv or json reports after every cleanup run.

## Usage
```
$ cloudkeeper -v --cleanup --report-cleanups-path /var/local/cloudkeeper/cleanup_reports/

OR

$ cloudkeeper -v --cleanup \
    --report-cleanups-path /var/local/cloudkeeper/cleanup_reports/ \
    --report-cleanups-format csv \
    --report-cleanups-add-attr instance_cores instance_memory volume_size
```

## List of arguments
```
  --report-cleanups-path REPORT_CLEANUPS_PATH
                        Path to Cleanup Reports Directory
  --report-cleanups-format {json,csv}
                        File Format for Cleanup Reports (default: json)
  --report-cleanups-add-attr REPORT_CLEANUPS_ADD_ATTR [REPORT_CLEANUPS_ADD_ATTR ...]
                        Additional resource attributes to include in CSV Cleanup Reports
```
