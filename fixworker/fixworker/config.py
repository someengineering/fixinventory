from concurrent.futures import ThreadPoolExecutor, TimeoutError
from fixlib.graph import GraphMergeKind
from fixlib.config import Config
from fixlib.proc import num_default_threads
from fixlib.baseplugin import BaseCollectorPlugin
from fixlib.logger import log
from attrs import define, field, frozen
from typing import ClassVar, Optional, List, Type, Dict

_default_collectors: List[str] = []


@frozen
class PluginAutoEnabledResult:
    cloud: str
    auto_enableable: bool


def add_config(config: Config, collector_plugins: List[Type[BaseCollectorPlugin]]) -> None:
    set_default_collectors(collector_plugins)
    config.add_config(FixWorkerConfig)


def set_default_collectors(collector_plugins: List[Type[BaseCollectorPlugin]]) -> None:
    global _default_collectors

    def plugin_auto_enabled(plugin: Type[BaseCollectorPlugin]) -> PluginAutoEnabledResult:
        return PluginAutoEnabledResult(plugin.cloud, plugin.auto_enableable())

    try:
        with ThreadPoolExecutor(max_workers=20, thread_name_prefix="AutoDiscovery") as executor:
            for plugin_result in executor.map(plugin_auto_enabled, collector_plugins, timeout=10):
                if plugin_result.auto_enableable and plugin_result.cloud not in _default_collectors:
                    _default_collectors.append(plugin_result.cloud)
    except TimeoutError:
        log.error("Timeout while getting auto-enabled collectors")
    except Exception as e:
        log.error(f"Unhandled exception while getting auto-enabled collectors: {e}")


@define
class HomeDirectoryFile:
    kind: ClassVar[str] = "fixworker_home_directory_file"
    path: str = field(metadata={"description": "Path to the file"})
    content: str = field(metadata={"description": "Content of the file", "ui-hint": "multiline"})


@define
class FixWorkerConfig:
    kind: ClassVar[str] = "fixworker"
    collector: List[str] = field(
        factory=lambda: _default_collectors,
        metadata={"description": "List of collectors to run", "restart_required": True},
    )
    graph: str = field(
        default="fix",
        metadata={"description": "Name of the graph to import data into and run searches on"},
    )
    timeout: int = field(default=10800, metadata={"description": "Collection/cleanup timeout in seconds"})
    pool_size: int = field(default=5, metadata={"description": "Collector thread/process pool size"})
    graph_sender_pool_size: int = field(
        default=5, metadata={"description": "Maximum number of graphs to send to the core concurrently"}
    )
    fork_process: bool = field(default=True, metadata={"description": "Use forked process instead of threads"})
    graph_merge_kind: GraphMergeKind = field(
        default=GraphMergeKind.account,
        metadata={"description": "Resource kind to merge graph at (cloud or account)"},
    )
    debug_dump_json: bool = field(default=False, metadata={"description": "Dump the generated JSON data to disk"})
    tempdir: Optional[str] = field(default=None, metadata={"description": "Directory to create temporary files in"})
    cleanup: bool = field(default=False, metadata={"description": "Enable cleanup of resources"})
    cleanup_pool_size: int = field(
        factory=lambda: num_default_threads() * 2,
        metadata={"description": "How many cleanup threads to run in parallel"},
    )
    cleanup_dry_run: bool = field(
        default=True,
        metadata={"description": "Do not actually cleanup resources, just create log messages"},
    )
    no_tls: bool = field(
        default=False,
        metadata={
            "description": "Disable TLS for the web server, even if Fix Core uses TLS.",
            "restart_required": True,
        },
    )
    web_host: str = field(
        default="::",
        metadata={
            "description": "IP address to bind the web server to",
            "restart_required": True,
        },
    )
    web_port: int = field(
        default=9956,
        metadata={
            "description": "Web server tcp port to listen on",
            "restart_required": True,
        },
    )
    web_path: str = field(
        default="/",
        metadata={
            "description": "Web root in browser (change if running behind an ingress proxy)",
            "restart_required": True,
        },
    )
    write_files_to_home_dir: List[HomeDirectoryFile] = field(
        factory=list,
        metadata={
            "description": "Deprecated. Use files_in_home_dir instead.",
            "restart_required": True,
        },
    )
    # optional for backwards compatibility
    files_in_home_dir: Optional[Dict[str, str]] = field(
        factory=dict,
        metadata={
            "description": (
                "All entries that are defined in this section are created as files on demand.\n"
                "Use this option to define .aws/credentials, .kube/config file or other "
                "credential files that should be passed to the worker as file.\n"
                "The key is the path to the file, the value is the content of the file."
            ),
            "restart_required": True,
        },
    )

    def all_files_in_home_dir(self) -> List[HomeDirectoryFile]:
        files = self.write_files_to_home_dir.copy()
        if self.files_in_home_dir is not None:
            for path, content in self.files_in_home_dir.items():
                files.append(HomeDirectoryFile(path=path, content=content))
        return files
