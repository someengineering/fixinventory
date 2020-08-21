import cloudkeeper.logging
import threading
import yaml
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import BaseResource, BaseCloud, BaseAccount, BaseRegion
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener, dispatch_event


log = cloudkeeper.logging.getLogger('cloudkeeper.' + __name__)


class ProtectSnowflakesPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'protect_snowflakes'
        self.exit = threading.Event()
        if ArgumentParser.args.protect_snowflakes_config:
            self.config = ProtectSnowflakesConfig(config_file=ArgumentParser.args.protect_snowflakes_config)
            self.config.read()  # initial read to ensure config format is valid
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(EventType.COLLECT_FINISH, self.protect_snowflakes, blocking=True, timeout=900)
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.protect_snowflakes)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def protect_snowflakes(self, event: Event):
        log.debug('Protect Snowflakes called')
        self.config.read()  # runtime read in case config file was updated since last run
        graph = event.data
        with graph.lock.read_access:
            for node in graph.nodes:
                cloud = node.cloud(graph)
                account = node.account(graph)
                region = node.region(graph)

                if (
                    not isinstance(node, BaseResource)
                    or isinstance(node, BaseCloud)
                    or isinstance(node, BaseAccount)
                    or isinstance(node, BaseRegion)
                    or not isinstance(cloud, BaseCloud)
                    or not isinstance(account, BaseAccount)
                    or not isinstance(region, BaseRegion)
                    or node.protected
                    or node.phantom
                    or cloud.id not in self.config
                    or account.id not in self.config[cloud.id]
                    or region.id not in self.config[cloud.id][account.id]
                    or node.resource_type not in self.config[cloud.id][account.id][region.id]
                    or node.id not in self.config[cloud.id][account.id][region.id][node.resource_type]
                ):
                    continue

                log_msg = "Snowflake protection configured for this Node - burning protection fuse"
                log.info(f"Protecting {node.resource_type} {node.dname} in cloud {cloud.name} account {account.dname} region {region.name}: {log_msg}")
                node.log(log_msg)
                node.protected = True

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--protect-snowflakes-config', help='Path to Protect Snowflakes Plugin Config', default=None, dest='protect_snowflakes_config')

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down Protect Snowflakes Plugin')
        self.exit.set()


class ProtectSnowflakesConfig(dict):
    def __init__(self, *args, config_file: str = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.config_file = config_file

    def read(self) -> bool:
        try:
            if not self.config_file:
                raise ValueError('Attribute config_file is not set on ProtectSnowflakesConfig() instance')

            with open(self.config_file) as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
            if self.validate(config):
                self.update(config)
        except Exception:
            log.exception(f'Error while reading {self.config_file}')
            reason = "Snowflake Protection failed to validate config - Resource Protection can't be guaranteed - configuration fix required!"
            dispatch_event(Event(EventType.SHUTDOWN, {'reason': reason, 'emergency': True}), blocking=True)
        else:
            return True
        return False

    @staticmethod
    def validate(config) -> bool:
        if not isinstance(config, dict):
            raise ValueError('Config is no dict')

        for cloud_id, account_data in config.items():
            if not isinstance(cloud_id, str):
                raise ValueError(f'Cloud ID {cloud_id} is no string')
            if not isinstance(account_data, dict):
                raise ValueError(f'Account Data {account_data} is no dict')

            for account_id, region_data in account_data.items():
                if not isinstance(account_id, str):
                    raise ValueError(f'Account ID {account_id} is no string')
                if not isinstance(region_data, dict):
                    raise ValueError(f'Region Data {region_data} is no dict')

                for region_id, resource_data in region_data.items():
                    if not isinstance(region_id, str):
                        raise ValueError(f'Region ID {region_id} is no string')
                    if not isinstance(resource_data, dict):
                        raise ValueError(f'Resource Data {resource_data} is no dict')

                    for resource_type, resource_list in resource_data.items():
                        if not isinstance(resource_type, str):
                            raise ValueError(f'Resource Type {resource_type} is no string')
                        if not isinstance(resource_list, list):
                            raise ValueError(f'Resource List {resource_list} is no list')

                        for resource_id in resource_list:
                            if not isinstance(resource_id, str):
                                raise ValueError(f'Resource ID {resource_id} is no string')
        return True
