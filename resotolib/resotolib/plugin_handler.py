from typing import Any, Dict, List, Type, Optional

from resotolib.types import DecoratedFn, Json

definitions = "__task_definitions"


def task_definitions(clazz: Type[Any]) -> List[Json]:
    return getattr(clazz, definitions, [])


class _WorkerTaskDecorator:
    """
    A final decorator is called by the interpreter once after the class is defined.
    (Not the case for decorators with attributes)
    This decorator will maintain all decorated methods on the class side.
    Use task_definitions(clazz) to get all task definitions of a specific class.
    """

    def __init__(
        self, fn: DecoratedFn, task_name: str, task_filter: Dict[str, List[str]], expects_resource: bool
    ) -> None:
        self.fn = fn
        self.task_name = task_name
        self.task_filter = task_filter
        self.expects_resource = expects_resource

    def __set_name__(self, owner, name):
        # store this definition on the owners side (class)
        if getattr(owner, definitions, None) is None:
            setattr(owner, definitions, [])
        getattr(owner, definitions).append(
            {
                "task_name": self.task_name,
                "task_filter": self.task_filter,
                "expects_resource": self.expects_resource,
                "handler": self.fn,
            }
        )
        # make the function available at the call side (class)
        setattr(owner, name, self.fn)

    def __call__(self) -> DecoratedFn:
        return self.fn


# noinspection PyPep8Naming
class resource_command:
    """
    In case you want to expose a method as worker task to the core, you can use this decorator.
    Annotate the method with the name of the task, as well as the filter attributes.
    The worker will make sure to call this method when a task is received.a

    Expected signature of the underlying method:

    @resource_command(name="cmd_name", filter={"cloud": ["aws"]})
    def call_name(self, resource: Json, argument: str) -> Json:
       pass
    """

    def __init__(self, name: str, filter: Optional[Dict[str, List[str]]] = None) -> None:
        self.name = name
        self.filter = filter or {}

    def __call__(self, fn: DecoratedFn) -> DecoratedFn:
        return _WorkerTaskDecorator(fn, self.name, self.filter, expects_resource=True)
