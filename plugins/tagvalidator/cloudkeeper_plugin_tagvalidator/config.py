import configparser
import cloudkeeper.logging
from collections import defaultdict

log = cloudkeeper.logging.getLogger("cloudkeeper." + __name__)


class TagValidatorConfig:
    def __init__(self, config_file):
        self.config_file = config_file

    # TODO: the supported config structure has grown too complex.
    # Refactor all of this to use pyyaml instead of configparser.
    def read_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        defaults = defaultdict(dict)
        cacfg = defaultdict(dict)
        for section in config.sections():
            if (
                "cloud" in config[section] and "account" in config[section]
            ):  # configuration of a cloud account
                cloud = config[section]["cloud"]
                account = config[section]["account"]
                cacfg[cloud][account] = {}

                log.debug(f"Reading config for account {account} in cloud {cloud}")

                for key, value in config[section].items():
                    if key in ("cloud", "account"):
                        continue
                    if " " in key:
                        classname, tag = key.split(" ", 1)
                        region = "*"
                        if " " in tag:
                            region, tag = tag.split(" ", 1)
                        classname = classname.lower()
                        if classname not in cacfg[cloud][account]:
                            cacfg[cloud][account][classname] = {}
                        cacfg[cloud][account][classname][tag] = {}
                        cacfg[cloud][account][classname][tag][region] = value
                    else:
                        log.error(f"Invalid config key {key}")
            else:  # configuration of a resource class
                classname = str(section).lower()
                for tag, value in config[section].items():
                    region = "*"
                    if " " in tag:
                        region, tag = tag.split(" ", 1)
                    if "\n" in value:
                        value = str(value).splitlines()
                    defaults[classname][tag] = {}
                    defaults[classname][tag][region] = value

        for cloud, accounts in cacfg.items():
            for account, class_config in accounts.items():
                for classname, default_class_config in defaults.items():
                    if classname not in class_config:
                        class_config[classname] = default_class_config
                    else:
                        for tag, default_tag_config in default_class_config.items():
                            if tag not in class_config[classname]:
                                class_config[classname][tag] = default_tag_config
                            else:
                                for region, tag_value in default_tag_config.items():
                                    if region not in class_config[classname][tag]:
                                        class_config[classname][tag][region] = tag_value

        return dict(cacfg)
