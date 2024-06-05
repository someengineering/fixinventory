import asyncio
import shutil
import tempfile
from asyncio import Queue
from collections import defaultdict
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import AsyncGenerator, Iterator, Dict, Any, Generator
from typing import List, Optional
from typing import Tuple, AsyncIterator, cast

from aiohttp import ClientSession
from aiohttp.hdrs import METH_ANY
from aiohttp.test_utils import TestServer
from aiohttp.web import Request, Response, Application, route
from arango.client import ArangoClient
from arango.database import StandardDatabase
from attr import evolve
from pytest import fixture
from rich.console import Console

from fixcore.action_handlers.merge_outer_edge_handler import MergeOuterEdgesHandler
from fixcore.analytics import AnalyticsEventSender, InMemoryEventSender, NoEventSender
from fixcore.cli.cli import CLIService
from fixcore.cli.command import (
    alias_names,
    all_commands,
)
from fixcore.config import ConfigHandler, ConfigEntity, ConfigValidation, ConfigOverride
from fixcore.config.config_handler_service import ConfigHandlerService
from fixcore.config.core_config_handler import CoreConfigHandler
from fixcore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from fixcore.core_config import (
    GraphUpdateConfig,
    CoreConfig,
    EditableConfig,
    DatabaseConfig,
    RuntimeConfig,
    CustomCommandsConfig,
    SnapshotsScheduleConfig,
    RunConfig,
)
from fixcore.db import runningtaskdb, SystemData, deferredouteredgedb, reportdb
from fixcore.db.async_arangodb import AsyncArangoDB
from fixcore.db.db_access import DbAccess
from fixcore.db.deferredouteredgedb import DeferredOuterEdgeDb
from fixcore.db.graphdb import ArangoGraphDB, EventGraphDB
from fixcore.db.jobdb import JobDb
from fixcore.db.modeldb import model_db
from fixcore.db.packagedb import PackageEntityDb, app_package_entity_db
from fixcore.db.reportdb import ReportCheckDb, BenchmarkDb
from fixcore.db.runningtaskdb import RunningTaskDb
from fixcore.db.system_data_db import SystemDataDb
from fixcore.db.timeseriesdb import TimeSeriesDB
from fixcore.dependencies import DirectTenantDependencyProvider, TenantDependencies
from fixcore.graph_manager.graph_manager import GraphManager
from fixcore.ids import SubscriberId, WorkerId, TaskDescriptorId, GraphName
from fixcore.infra_apps.local_runtime import LocalfixcoreAppRuntime
from fixcore.infra_apps.package_manager import PackageManager
from fixcore.message_bus import (
    MessageBus,
    Message,
    Event,
    Action,
    ActionDone,
)
from fixcore.model.adjust_node import NoAdjust
from fixcore.model.db_updater import GraphMerger
from fixcore.model.graph_access import EdgeTypes, Section
from fixcore.model.model import Model, Kind, ComplexKind, Property, SyntheticProperty, StringKind
from fixcore.model.resolve_in_graph import GraphResolver
from fixcore.model.resolve_in_graph import NodePath
from fixcore.model.typed_model import to_js
from fixcore.query.template_expander import TemplateExpander
from fixcore.report import (
    Benchmark,
    ReportCheck,
    ReportSeverity,
    Remediation,
    CheckCollection,
)
from fixcore.report.inspector_service import InspectorService
from fixcore.system_start import empty_config, parse_args
from fixcore.task.model import Subscriber, Subscription
from fixcore.task.scheduler import APScheduler
from fixcore.task.subscribers import SubscriptionHandler, SubscriptionHandlerService
from fixcore.task.task_dependencies import TaskDependencies
from fixcore.task.task_description import (
    Step,
    PerformAction,
    WaitForEvent,
    EmitEvent,
    StepErrorBehaviour,
    EventTrigger,
    RunningTask,
    ExecuteCommand,
    TaskSurpassBehaviour,
    Job,
    Workflow,
    TimeTrigger,
    WaitForCollectDone,
)
from fixcore.task.task_handler import TaskHandlerService
from fixcore.types import Json
from fixcore.user import UserManagement
from fixcore.user.user_management import UserManagementService
from fixcore.util import value_in_path, uuid_str, utc
from fixcore.web.auth import AuthHandler
from fixcore.web.certificate_handler import CertificateHandler, CertificateHandlerWithCA
from fixcore.worker_task_queue import WorkerTaskQueue, WorkerTaskDescription, WorkerTask, WorkerTaskName
from fixlib.x509 import bootstrap_ca
from tests.fixcore import create_graph
from tests.fixcore.db.entitydb import InMemoryDb
from tests.fixcore.model import ModelHandlerStatic
from tests.fixcore.query.template_expander_test import InMemoryTemplateExpander


@fixture
def default_config() -> CoreConfig:
    ed = EditableConfig()
    return CoreConfig(
        api=ed.api,
        cli=ed.cli,
        db=DatabaseConfig(),
        graph_update=ed.graph_update,
        # We use this flag explicitly - otherwise it is picked up by env vars
        runtime=RuntimeConfig(usage_metrics=False),
        workflows=ed.workflows,
        custom_commands=CustomCommandsConfig(),
        snapshots=SnapshotsScheduleConfig(),
        args=parse_args(["--analytics-opt-out"]),
        run=RunConfig(),
        timeseries=ed.timeseries,
    )


@fixture
async def message_bus() -> MessageBus:
    return MessageBus()


@fixture
def job_db() -> JobDb:
    return InMemoryDb[str, Job](Job, lambda x: x.id)


@fixture
def event_sender() -> InMemoryEventSender:
    return InMemoryEventSender()


@fixture
def local_client() -> ArangoClient:
    return ArangoClient(hosts="http://localhost:8529")


@fixture
def system_db(local_client: ArangoClient) -> StandardDatabase:
    return local_client.db()


@fixture
async def async_db(test_db: StandardDatabase) -> AsyncArangoDB:
    return AsyncArangoDB(test_db)


@fixture
async def all_events(message_bus: MessageBus) -> AsyncGenerator[List[Message], None]:
    events: List[Message] = []

    async def gather_events() -> None:
        async with message_bus.subscribe(SubscriberId("test")) as event_queue:
            while True:
                events.append(await event_queue.get())

    run_gather = asyncio.create_task(gather_events())
    try:
        yield events
    finally:
        run_gather.cancel()


@fixture
def test_db(local_client: ArangoClient, system_db: StandardDatabase) -> StandardDatabase:
    if not system_db.has_user("test"):
        system_db.create_user("test", "test", True)

    if not system_db.has_database("test"):
        system_db.create_database("test", [{"username": "test", "password": "test", "active": True}])

    # Connect to "test" database as "test" user.
    return local_client.db("test", username="test", password="test")


@fixture
async def graph_db(async_db: AsyncArangoDB) -> ArangoGraphDB:
    graph_db = ArangoGraphDB(async_db, GraphName("ns"), NoAdjust(), GraphUpdateConfig())
    await graph_db.create_update_schema()
    await model_db(async_db, "ns_model").create_update_schema()
    await async_db.truncate(graph_db.in_progress)
    return graph_db


@fixture
async def running_task_db(async_db: AsyncArangoDB) -> RunningTaskDb:
    task_db = runningtaskdb.running_task_db(async_db, "running_tasks")
    await task_db.create_update_schema()
    await task_db.wipe()
    return task_db


@fixture
async def report_check_db(async_db: AsyncArangoDB) -> ReportCheckDb:
    check_db = reportdb.report_check_db(async_db, "report_checks")
    await check_db.create_update_schema()
    await check_db.wipe()
    return check_db


@fixture
async def benchmark_db(async_db: AsyncArangoDB) -> BenchmarkDb:
    benchmark = reportdb.benchmark_db(async_db, "report_benchmarks")
    await benchmark.create_update_schema()
    await benchmark.wipe()
    return benchmark


@fixture
async def pending_deferred_edge_db(async_db: AsyncArangoDB) -> DeferredOuterEdgeDb:
    edges_db = deferredouteredgedb.deferred_outer_edge_db(async_db, "pending_deferred_edge")
    await edges_db.create_update_schema()
    await edges_db.wipe()
    return edges_db


@fixture
async def timeseries_db(async_db: AsyncArangoDB, default_config: CoreConfig) -> TimeSeriesDB:
    db = TimeSeriesDB(async_db, "ts", default_config)
    await db.create_update_schema()
    return db


@fixture()
def db_access(graph_db: ArangoGraphDB) -> DbAccess:
    access = DbAccess(graph_db.db.db, NoEventSender(), NoAdjust(), empty_config())
    return access


@fixture
async def package_entity_db(async_db: AsyncArangoDB) -> PackageEntityDb:
    package_entity_db = app_package_entity_db(async_db, "test_package_entity_db")
    await package_entity_db.create_update_schema()
    await package_entity_db.wipe()
    return package_entity_db


@fixture
def foo_kinds() -> List[Kind]:
    base = ComplexKind(
        "base",
        [],
        [
            Property("id", "string", required=True),
            Property("kind", "string", required=True),
            Property("ctime", "datetime"),
        ],
        aggregate_root=False,
    )
    foo = ComplexKind(
        "foo",
        ["base"],
        [
            Property("name", "string"),
            Property("some_int", "int32"),
            Property("some_string", "string"),
            Property("now_is", "datetime"),
            Property("ctime", "datetime"),
            Property("age", "trafo.duration_to_datetime", False, SyntheticProperty(["ctime"])),
        ],
        successor_kinds={EdgeTypes.default: ["bla"]},
    )
    inner = ComplexKind("inner", [], [Property("name", "string"), Property("inner", "inner[]")], aggregate_root=False)
    bla = ComplexKind(
        "bla",
        ["base"],
        [
            Property("name", "string"),
            Property("now", "date"),
            Property("f", "int32"),
            Property("g", "int32[]"),
            Property("h", "inner"),
        ],
        successor_kinds={EdgeTypes.default: ["bla"]},
    )
    cloud = ComplexKind("cloud", ["foo"], [Property("nick", "string")])
    account = ComplexKind("account", ["foo"], [Property("nick", "string")])
    region = ComplexKind("region", ["foo"], [Property("nick", "string")])
    parent = ComplexKind("parent", ["foo"], [Property("nick", "string")])
    child = ComplexKind("child", ["foo"], [Property("nick", "string")])
    some_complex = ComplexKind(
        "some_complex",
        ["base"],
        [
            Property("cloud", "cloud"),
            Property("account", "account"),
            Property("parents", "parent[]"),
            Property("children", "child[]"),
            Property("nested", "inner[]"),
        ],
        successor_kinds={EdgeTypes.default: ["bla"]},
    )

    return [base, foo, bla, cloud, account, region, parent, child, inner, some_complex]


@fixture
def foo_model(foo_kinds: List[Kind]) -> Model:
    return Model.from_kinds(foo_kinds)


@fixture
def person_model() -> Model:
    zip = StringKind("zip")
    base = ComplexKind(
        "Base",
        [],
        [
            Property("id", "string", required=True, description="Some id"),
            Property("kind", "string", required=True, description="Kind of this node."),
            Property("list", "string[]", description="A list of strings."),
            Property("tags", "dictionary[string, string]", description="Key/value pairs."),
            Property("mtime", "datetime", description="Modification time of this node."),
        ],
        metadata={"icon": "icon.svg"},
    )
    address = ComplexKind(
        "Address",
        ["Base"],
        [
            Property("zip", "zip", description="The zip code."),
            Property("city", "string", required=True, description="The name of the city.\nAnd another line."),
        ],
        metadata={"icon": "address.svg"},
    )
    person = ComplexKind(
        "Person",
        ["Base"],
        [
            Property("name", "string", description="The name of the person."),
            Property("address", "Address", description="The address of the person."),
            Property("other_addresses", "dictionary[string, Address]", description="Other addresses."),
            Property("addresses", "Address[]", description="The list of addresses."),
            Property("any", "any", description="Some arbitrary value."),
        ],
        successor_kinds={EdgeTypes.default: ["Address"]},
    )
    any_foo = ComplexKind(
        "any_foo",
        ["Base"],
        [
            Property("foo", "any", description="Some foo value."),
            Property("test", "string", description="Some test value."),
        ],
    )
    cloud = ComplexKind("cloud", ["Base"], [])
    account = ComplexKind("account", ["Base"], [])
    region = ComplexKind("region", ["Base"], [])
    parent = ComplexKind("parent", ["Base"], [])
    child = ComplexKind("child", ["Base"], [])

    return Model.from_kinds([zip, person, address, base, any_foo, cloud, account, region, parent, child])


@fixture
async def filled_graph_db(graph_db: ArangoGraphDB, foo_model: Model) -> ArangoGraphDB:
    graph_db.db.collection(graph_db.node_history).truncate()
    if await graph_db.db.has_collection("model"):
        graph_db.db.collection("model").truncate()
    await graph_db.wipe()
    await graph_db.merge_graph(create_graph("yes or no"), foo_model)
    return graph_db


@fixture
async def event_graph_db(filled_graph_db: ArangoGraphDB, event_sender: AnalyticsEventSender) -> EventGraphDB:
    return EventGraphDB(filled_graph_db, event_sender)


@fixture
def expander() -> InMemoryTemplateExpander:
    return InMemoryTemplateExpander()


@fixture
async def task_queue() -> AsyncIterator[WorkerTaskQueue]:
    wtq = WorkerTaskQueue()
    await wtq.start()
    yield wtq
    await wtq.stop()


@fixture
def performed_by() -> Dict[str, List[str]]:
    return defaultdict(list)


@fixture
def incoming_tasks() -> List[WorkerTask]:
    return []


@fixture
async def worker(
    task_queue: WorkerTaskQueue, performed_by: Dict[str, List[WorkerId]], incoming_tasks: List[WorkerTask]
) -> AsyncGenerator[Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription], None]:
    success = WorkerTaskDescription("success_task")
    fail = WorkerTaskDescription("fail_task")
    wait = WorkerTaskDescription("wait_task")
    tag = WorkerTaskDescription(WorkerTaskName.tag)
    validate_config = WorkerTaskDescription(WorkerTaskName.validate_config)

    async def do_work(worker_id: WorkerId, task_descriptions: List[WorkerTaskDescription]) -> None:
        async with task_queue.attach(worker_id, task_descriptions) as tasks:
            while True:
                task: WorkerTask = await tasks.get()
                incoming_tasks.append(task)
                performed_by[task.id].append(worker_id)
                if task.name == success.name:
                    await task_queue.acknowledge_task(worker_id, task.id, {"result": "done!"})
                elif task.name == fail.name:
                    await task_queue.error_task(worker_id, task.id, ";)")
                elif task.name == wait.name:
                    # if we come here, neither success nor failure was given, ignore the task
                    pass
                elif task.name == WorkerTaskName.validate_config:
                    cfg_id = task.attrs["config_id"]
                    if cfg_id == "invalid_config":
                        await task_queue.error_task(worker_id, task.id, "Invalid Config ;)")
                    else:
                        await task_queue.acknowledge_task(worker_id, task.id, None)
                elif task.name == WorkerTaskName.tag:
                    node = task.data["node"]
                    for key in GraphResolver.resolved_ancestors.keys():
                        for section in Section.content:
                            if section in node:
                                node[section].pop(key, None)

                    # update or delete tags
                    if "tags" not in node:
                        node["tags"] = {}

                    if task.data.get("delete"):
                        for a in task.data.get("delete"):  # type: ignore
                            node["tags"].pop(a, None)
                    elif task.data.get("update"):
                        for k, v in task.data.get("update").items():  # type: ignore
                            node["tags"][k] = v

                    # for testing purposes: change revision number
                    kind: str = value_in_path(node, NodePath.reported_kind)  # type: ignore
                    if kind == "bla":
                        node["revision"] = "changed"

                    await task_queue.acknowledge_task(worker_id, task.id, node)
                else:
                    await task_queue.error_task(worker_id, task.id, "Don't know how to handle this task")

    workers = [
        asyncio.create_task(do_work(WorkerId(f"w{a}"), [success, fail, wait, tag, validate_config]))
        for a in range(0, 4)
    ]
    await asyncio.sleep(0)

    yield success, fail, wait
    for worker in workers:
        worker.cancel()


@fixture
def cert_handler() -> Iterator[CertificateHandler]:
    config = empty_config()
    ca_key, ca_cert = bootstrap_ca()
    temp = TemporaryDirectory()
    key, cert = CertificateHandlerWithCA._create_host_certificate(config.api.host_certificate, ca_key, ca_cert)
    yield CertificateHandlerWithCA(config, ca_key, ca_cert, key, cert, Path(temp.name))
    temp.cleanup()


@fixture
def config_handler(task_queue: WorkerTaskQueue, worker: Any, message_bus: MessageBus) -> ConfigHandlerService:
    # Note: the worker fixture is required, since it starts worker tasks
    cfg_db = InMemoryDb(ConfigEntity, lambda c: c.id)
    validation_db = InMemoryDb(ConfigValidation, lambda c: c.id)
    model_db = InMemoryDb(Kind, lambda c: c.fqn)  # type: ignore
    event_sender = InMemoryEventSender()
    core_config = cast(CoreConfig, SimpleNamespace())
    override_service = cast(ConfigOverride, SimpleNamespace(get_override=lambda _: {}, get_all_overrides=lambda: {}))
    return ConfigHandlerService(
        cfg_db, validation_db, model_db, task_queue, message_bus, event_sender, core_config, override_service
    )


@fixture
def core_config_handler_exits() -> List[bool]:
    return []


@fixture
async def core_config_handler(
    message_bus: MessageBus,
    task_queue: WorkerTaskQueue,
    config_handler: ConfigHandler,
    inspector_service: InspectorService,
    core_config_handler_exits: List[bool],
) -> CoreConfigHandler:
    def on_exit() -> None:
        core_config_handler_exits.append(True)

    config = empty_config()
    sender = InMemoryEventSender()
    return CoreConfigHandler(config, message_bus, task_queue, config_handler, sender, inspector_service, on_exit)


@fixture
async def core_config_handler_started(core_config_handler: CoreConfigHandler) -> AsyncIterator[CoreConfigHandler]:
    await core_config_handler.start()
    yield core_config_handler
    await core_config_handler.stop()


@fixture
async def dependencies(
    filled_graph_db: ArangoGraphDB,
    message_bus: MessageBus,
    event_sender: InMemoryEventSender,
    foo_model: Model,
    task_queue: WorkerTaskQueue,
    worker: Tuple[WorkerTaskDescription, WorkerTaskDescription, WorkerTaskDescription],
    expander: TemplateExpander,
    config_handler: ConfigHandler,
    cert_handler: CertificateHandler,
    user_management: UserManagement,
) -> AsyncIterator[TenantDependencies]:
    db_access = DbAccess(filled_graph_db.db.db, event_sender, NoAdjust(), empty_config())
    model_handler = ModelHandlerStatic(foo_model)
    config = empty_config(["--graphdb-database", "test", "--graphdb-username", "test", "--graphdb-password", "test"])
    deps = TenantDependencies(
        message_bus=message_bus,
        event_sender=event_sender,
        db_access=db_access,
        model_handler=model_handler,
        worker_task_queue=task_queue,
        config=config,
        template_expander=expander,
        forked_tasks=Queue(),
        config_handler=config_handler,
        cert_handler=cert_handler,
        user_management=user_management,
    )
    await db_access.start()
    yield deps
    await db_access.stop()
    await deps.stop()


@fixture
async def graph_merger(
    foo_model: Model, event_sender: AnalyticsEventSender, default_config: CoreConfig, message_bus: MessageBus
) -> GraphMerger:
    model_handler = ModelHandlerStatic(foo_model)
    return GraphMerger(model_handler, event_sender, default_config, message_bus)


@fixture
async def task_dependencies(graph_merger: GraphMerger, subscription_handler: SubscriptionHandler) -> TaskDependencies:
    return TaskDependencies(graph_merger, subscription_handler.subscribers_by_event)


@fixture
def cli(dependencies: TenantDependencies) -> CLIService:
    env = {"graph": "ns", "section": "reported"}
    return CLIService(dependencies, all_commands(dependencies), env, alias_names())


@fixture
def benchmark() -> Benchmark:
    return Benchmark(
        id="test",
        framework="test",
        documentation="test",
        version="1.5",
        clouds=["collector"],
        title="test_benchmark",
        description="test_benchmark",
        checks=[],
        children=[
            CheckCollection(
                title="Section 1",
                description="Some description",
                checks=["test_test_search"],
                documentation="test",
                children=[],
            ),
            CheckCollection(
                title="Section 2",
                description="Some description",
                documentation="Some other documentation",
                checks=["test_test_cmd"],
                children=[],
            ),
        ],
    )


@fixture
def inspection_checks() -> List[ReportCheck]:
    return [
        ReportCheck(
            id="test_test_search",
            provider="test",
            service="test",
            title="search",
            result_kinds=["foo"],
            categories=["test"],
            severity=ReportSeverity.medium,
            risk="Some serious risk",
            # we use a query with a template here
            detect={"fix": "is({{foo_kind}})"},
            default_values={"foo_kind": "foo"},
            remediation=Remediation(text="Fix it now", url="https://example.test", action={}),
        ),
        ReportCheck(
            id="test_test_cmd",
            provider="test",
            service="test",
            title="cmd",
            result_kinds=["foo"],
            categories=["test"],
            severity=ReportSeverity.critical,
            detect={"fix_cmd": "search is(foo) | jq --no-rewrite ."},
            risk="Some other risk.",
            remediation=Remediation(text="Fix it", url="https://example.link", action={}),
        ),
    ]


@fixture
async def inspector_service(
    cli: CLIService, benchmark: Benchmark, inspection_checks: List[ReportCheck]
) -> InspectorService:
    async with InspectorService(cli) as service:
        for check in inspection_checks:
            await service.update_check(check)
        await service.update_benchmark(benchmark)
        cli.dependencies.lookup["inspector"] = service
        return service


@fixture
async def package_manager(
    cli: CLIService, config_handler: ConfigHandler, package_entity_db: PackageEntityDb
) -> PackageManager:
    async with PackageManager(package_entity_db, config_handler, lambda at: None, lambda s: None) as service:
        cli.dependencies.lookup["infra_apps_package_manager"] = service
        return service


@fixture
async def graph_manager(
    cli: CLIService,
    db_access: DbAccess,
    default_config: CoreConfig,
    core_config_handler: CoreConfigHandler,
    task_handler: TaskHandlerService,
) -> GraphManager:
    async with GraphManager(db_access, default_config, core_config_handler, task_handler) as service:
        cli.dependencies.lookup["graph_manager"] = service
        return service


@fixture
async def infra_apps_runtime(cli: CLIService) -> LocalfixcoreAppRuntime:
    runtime = LocalfixcoreAppRuntime(cli)
    cli.dependencies.lookup["infra_apps_runtime"] = runtime
    return runtime


@fixture
async def client_session() -> AsyncIterator[ClientSession]:
    session = ClientSession()
    yield session
    await session.close()


@fixture
def test_workflow() -> Workflow:
    return Workflow(
        TaskDescriptorId("test_workflow"),
        "Speakable name of workflow",
        [
            Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
            Step("act", PerformAction("collect"), timedelta(seconds=10)),
            Step("done", PerformAction("collect_done"), timedelta(seconds=10), StepErrorBehaviour.Stop),
        ],
        [EventTrigger("start me up"), TimeTrigger("1 1 1 1 1")],
    )


@fixture
def additional_workflows() -> List[Workflow]:
    return [
        Workflow(
            TaskDescriptorId("sleep_workflow"),
            "Speakable name of workflow",
            [Step("sleep", ExecuteCommand("sleep 0.1"), timedelta(seconds=10))],
            triggers=[],
            on_surpass=TaskSurpassBehaviour.Wait,
        ),
        Workflow(
            TaskDescriptorId("wait_for_collect_done"),
            "Wait for collect",
            [
                Step("wait", WaitForEvent("collected", {}), timedelta(seconds=10)),
                Step("wait_for_collect_done", WaitForCollectDone(), timedelta(seconds=10)),
            ],
            triggers=[],
            on_surpass=TaskSurpassBehaviour.Wait,
        ),
    ]


@fixture
def test_wait_workflow() -> Workflow:
    return Workflow(
        TaskDescriptorId("test_workflow"),
        "Speakable name of workflow",
        [
            Step("start", PerformAction("start_collect"), timedelta(seconds=10)),
            Step("wait", WaitForEvent("godot", {"a": 1}), timedelta(seconds=10)),
            Step("emit_event", EmitEvent(Event("hello", {"a": 1})), timedelta(seconds=10)),
            Step("collect", PerformAction("collect"), timedelta(seconds=10)),
            Step("done", PerformAction("collect_done"), timedelta(seconds=10), StepErrorBehaviour.Stop),
        ],
        [EventTrigger("start me up")],
    )


@fixture
def workflow_instance(
    task_dependencies: TaskDependencies,
    test_wait_workflow: Workflow,
) -> Tuple[RunningTask, Subscriber, Subscriber, Dict[str, List[Subscriber]]]:
    td = timedelta(seconds=100)
    sub1 = Subscription("start_collect", True, td)
    sub2 = Subscription("collect", True, td)
    sub3 = Subscription("collect_done", True, td)
    s1 = Subscriber.from_list(SubscriberId("s1"), [sub1, sub2, sub3])
    s2 = Subscriber.from_list(SubscriberId("s2"), [sub2, sub3])
    subscriptions = {"start_collect": [s1], "collect": [s1, s2], "collect_done": [s1, s2]}
    w, _ = RunningTask.empty(test_wait_workflow, evolve(task_dependencies, subscribers_by_event=lambda: subscriptions))
    w.received_messages = [
        Action("start_collect", w.id, "start"),
        ActionDone("start_collect", w.id, "start", s1.id),
        ActionDone("start_collect", w.id, "start", s2.id),
        Event("godot", {"a": 1, "b": 2}),
        Action("collect", w.id, "collect"),
        ActionDone("collect", w.id, "collect", s1.id),
    ]
    w.move_to_next_state()
    return w, s1, s2, subscriptions


@fixture
async def subscription_handler(message_bus: MessageBus) -> AsyncIterator[SubscriptionHandlerService]:
    async with SubscriptionHandlerService(message_bus) as handler:
        yield handler


@fixture
async def task_handler(
    running_task_db: RunningTaskDb,
    job_db: JobDb,
    message_bus: MessageBus,
    event_sender: AnalyticsEventSender,
    subscription_handler: SubscriptionHandler,
    graph_merger: GraphMerger,
    cli: CLIService,
    test_workflow: Workflow,
    additional_workflows: List[Workflow],
) -> AsyncGenerator[TaskHandlerService, None]:
    config = empty_config()
    task_handler = TaskHandlerService(
        running_task_db,
        job_db,
        message_bus,
        event_sender,
        subscription_handler,
        graph_merger,
        APScheduler(),
        cli,
        config,
    )
    task_handler.task_descriptions = additional_workflows + [test_workflow]
    cli.dependencies.lookup["task_handler"] = task_handler
    async with task_handler:
        yield task_handler


@fixture
def tmp_directory() -> Generator[str, None, None]:
    tmp_dir: Optional[str] = None
    try:
        tmp_dir = tempfile.mkdtemp()
        yield tmp_dir
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir)


@fixture
async def echo_http_server() -> AsyncIterator[Tuple[int, List[Tuple[Request, Json]]]]:
    requests = []

    async def add_request(request: Request) -> Response:
        requests.append((request, await request.json()))
        status = 500 if request.path.startswith("/fail") else 200
        return Response(status=status)

    app = Application()
    app.add_routes([route(METH_ANY, "/{tail:.+}", add_request)])
    server = TestServer(app)
    await server.start_server()
    yield server.port, requests  # type: ignore
    await server.close()


@fixture()
async def merge_handler(
    message_bus: MessageBus,
    subscription_handler: SubscriptionHandler,
    task_handler: TaskHandlerService,
    db_access: DbAccess,
    foo_model: Model,
) -> AsyncGenerator[MergeOuterEdgesHandler, None]:
    model_handler = ModelHandlerStatic(foo_model)
    handler = MergeOuterEdgesHandler(message_bus, subscription_handler, task_handler, db_access, model_handler)
    await handler.start()
    yield handler
    await handler.stop()


@fixture
def console_renderer() -> ConsoleRenderer:
    tty_columns, tty_rows = shutil.get_terminal_size(fallback=(80, 25))
    return ConsoleRenderer(tty_columns, tty_rows, ConsoleColorSystem.from_name(Console().color_system or "standard"))


@fixture
async def user_management(
    db_access: DbAccess, config_handler: ConfigHandler, event_sender: AnalyticsEventSender
) -> UserManagementService:
    return UserManagementService(db_access, config_handler, event_sender)


@fixture
async def system_data_db(test_db: StandardDatabase) -> AsyncIterator[SystemDataDb]:
    with suppress(Exception):
        system = SystemData(uuid_str(), utc(), 1, "test_version")
        test_db.insert_document("system_data", {"_key": "system", **to_js(system)}, overwrite=False)
    with suppress(Exception):
        test_db.insert_document(
            "system_data", {"_key": "ca", "key": "private_key", "certificate": "some cert"}, overwrite=False
        )
    async_db = AsyncArangoDB(test_db)
    yield SystemDataDb(async_db)
    test_db.collection("system_data").delete({"_key": "ca"})


@fixture
async def auth_handler(
    system_data_db: SystemDataDb,
    default_config: CoreConfig,
    cert_handler: CertificateHandler,
    dependencies: TenantDependencies,
) -> AsyncIterator[AuthHandler]:
    config = evolve(default_config, args=parse_args(["--psk", "test"]))
    provider = DirectTenantDependencyProvider(dependencies)
    async with AuthHandler(system_data_db, config, cert_handler, provider, set()) as auth:
        yield auth
