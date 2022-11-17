import pkg_resources
import inspect
from resotolib.logger import log
from typing import List, Optional, Type, Union, Dict, cast, Set
from resotolib.args import ArgumentParser
from resotolib.config import Config
from resotolib.baseplugin import BaseCollectorPlugin, BasePostCollectPlugin, BasePlugin, BaseActionPlugin, PluginType


class PluginLoader:
    """resoto plugin loader"""

    def __init__(self, plugin_type: Optional[PluginType] = None) -> None:
        # self.__plugins is a dict with key PluginType and value List
        # The List will hold all the Plugins of a PluginType
        # Current PluginTypes are COLLECTOR, CLI and PERSISTENT. So the Dict could look
        # something like this:
        # {
        #   PluginType.COLLECTOR: [AWSPlugin, GCPPlugin, AzurePlugin],
        #   PluginType.CLI: [CliDebugPlugin]
        #   PluginType.PERSISTENT: [SlackNotificationPlugin, VolumeCleanupPlugin]
        # }
        self._plugins: Dict[PluginType, List[Union[Type[BasePlugin], Type[BaseActionPlugin]]]] = {}
        self._initialized = False

        if plugin_type is not None:
            log.debug(f"Only loading plugins of type {plugin_type}")
            self._plugins[plugin_type] = []
        else:
            for plugin_type in PluginType:
                if plugin_type not in self._plugins:
                    log.debug(f"Loading plugins of type {plugin_type}")
                    self._plugins[plugin_type] = []

    def find_plugins(self) -> None:
        """Finds resoto plugins

        resoto Plugins have an entry point resoto.plugins.
        Any package resource with an entry point of that name will be handed to
        app_plugin() which validates that the package resource is a subclass of
        BasePlugin.
        """
        log.debug("Finding plugins")
        for entry_point in pkg_resources.iter_entry_points("resoto.plugins"):
            plugin = entry_point.load()
            self.add_plugin(plugin)
        self._initialized = True

    def add_plugin(self, plugin: Union[Type[BasePlugin], Type[BaseActionPlugin]]) -> bool:
        """Adds a Plugin class to the list of Plugins"""
        if (
            inspect.isclass(plugin)
            and not inspect.isabstract(plugin)
            and issubclass(plugin, (BasePlugin, BaseActionPlugin, BasePostCollectPlugin))
            and plugin.plugin_type in self._plugins
        ):
            log.debug(f"Found plugin {plugin} ({plugin.plugin_type.name})")
            if plugin not in self._plugins[plugin.plugin_type]:
                self._plugins[plugin.plugin_type].append(plugin)
        return True

    def plugins(
        self, plugin_type: PluginType
    ) -> List[Union[Type[BasePlugin], Type[BaseActionPlugin], Type[BasePostCollectPlugin]]]:
        """Returns the list of Plugins of a certain PluginType"""
        if not self._initialized:
            self.find_plugins()
        configured_collectors: Set[str] = set(Config.resotoworker.collector)

        if plugin_type == PluginType.POST_COLLECT and len(configured_collectors) > 0:
            post_collect_plugins = cast(List[Type[BasePostCollectPlugin]], self._plugins.get(plugin_type, []))
            return [
                plugin
                for plugin in post_collect_plugins
                if plugin.activate_with.issubset(configured_collectors) or plugin.name in configured_collectors
            ]

        if plugin_type == PluginType.COLLECTOR and len(configured_collectors) > 0:
            plugins: List[Type[BaseCollectorPlugin]] = self._plugins.get(plugin_type, [])  # type: ignore
            return [plugin for plugin in plugins if plugin.cloud in configured_collectors]

        return self._plugins.get(plugin_type, [])  # type: ignore

    def all_plugins(
        self, plugin_type: Optional[PluginType] = None
    ) -> List[Union[Type[BasePlugin], Type[BaseActionPlugin], Type[BasePostCollectPlugin]]]:
        if not self._initialized:
            self.find_plugins()
        if plugin_type is not None:
            return self._plugins.get(plugin_type, [])  # type: ignore
        return [plugin for plugins in self._plugins.values() for plugin in plugins]

    def add_plugin_args(self, arg_parser: ArgumentParser) -> None:
        """Add args to the arg parser"""
        if not self._initialized:
            self.find_plugins()
        log.debug("Adding plugin args")
        for type_plugins in self._plugins.values():  # iterate over all PluginTypes
            for plugin in type_plugins:  # iterate over each Plugin of each PluginType
                plugin.add_args(arg_parser)  # add that Plugin's args to the ArgumentParser

    def add_plugin_config(self, config: Config) -> None:
        """Add plugin config to the config object"""
        if not self._initialized:
            self.find_plugins()
        log.debug("Adding plugin config")
        for type_plugins in self._plugins.values():  # iterate over all PluginTypes
            for plugin in type_plugins:  # iterate over each Plugin of each PluginType
                plugin.add_config(config)
