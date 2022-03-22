import pkg_resources
import inspect
from resotolib.logging import log
from typing import List, Optional
from resotolib.args import ArgumentParser
from resotolib.config import Config
from resotolib.baseplugin import BasePlugin, BaseActionPlugin, PluginType


plugins = {}
initialized = False


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
        global plugins

        if plugin_type is not None:
            log.debug(f"Only loading plugins of type {plugin_type}")
            plugins[plugin_type] = []
        else:
            for plugin_type in PluginType:
                if plugin_type not in plugins:
                    log.debug(f"Loading plugins of type {plugin_type}")
                    plugins[plugin_type] = []

    def find_plugins(self) -> None:
        """Finds resoto plugins

        resoto Plugins have an entry point resoto.plugins.
        Any package resource with an entry point of that name will be handed to
        app_plugin() which validates that the package resource is a subclass of
        BasePlugin.
        """
        global initialized
        log.debug("Finding plugins")
        for entry_point in pkg_resources.iter_entry_points("resoto.plugins"):
            plugin = entry_point.load()
            self.add_plugin(plugin)
        initialized = True

    def add_plugin(self, plugin) -> bool:
        """Adds a Plugin class to the list of Plugins"""
        global plugins
        if (
            inspect.isclass(plugin)
            and not inspect.isabstract(plugin)
            and issubclass(plugin, (BasePlugin, BaseActionPlugin))
            and plugin.plugin_type in plugins
        ):
            log.debug(f"Found plugin {plugin} ({plugin.plugin_type.name})")
            if plugin not in plugins[plugin.plugin_type]:
                plugins[plugin.plugin_type].append(plugin)
        return True

    def plugins(self, plugin_type: PluginType) -> List:
        """Returns the list of Plugins of a certain PluginType"""
        if not initialized:
            self.find_plugins()
        if (
            plugin_type == PluginType.COLLECTOR
            and len(Config.resotoworker.collector) > 0
        ):
            return [
                plugin
                for plugin in plugins.get(plugin_type, [])
                if plugin.cloud in Config.resotoworker.collector
            ]
        return plugins.get(plugin_type, [])

    def add_plugin_args(self, arg_parser: ArgumentParser) -> None:
        """Add args to the arg parser"""
        if not initialized:
            self.find_plugins()
        log.debug("Adding plugin args")
        for type_plugins in plugins.values():  # iterate over all PluginTypes
            for Plugin in type_plugins:  # iterate over each Plugin of each PluginType
                Plugin.add_args(
                    arg_parser
                )  # add that Plugin's args to the ArgumentParser

    def add_plugin_config(self, config: Config) -> None:
        """Add plugin config to the config object"""
        if not initialized:
            self.find_plugins()
        log.debug("Adding plugin config")
        for type_plugins in plugins.values():  # iterate over all PluginTypes
            for Plugin in type_plugins:  # iterate over each Plugin of each PluginType
                Plugin.add_config(config)
