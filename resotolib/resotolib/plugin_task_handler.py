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
        self, fn: DecoratedFn, task_name: str, task_filter: Dict[str, List[str]], expect_resource: bool
    ) -> None:
        self.fn = fn
        self.task_name = task_name
        self.task_filter = task_filter
        self.expect_resource = expect_resource

    def __set_name__(self, owner, name):
        # store this definition on the owners side (class)
        if getattr(owner, definitions, None) is None:
            setattr(owner, definitions, [])
        getattr(owner, definitions).append(
            {
                "task_name": self.task_name,
                "task_filter": self.task_filter,
                "handler": self.fn,
                "expect_resource": self.expect_resource,
            }
        )
        # make the function available at the call side (class)
        setattr(owner, name, self.fn)

    def __call__(self) -> DecoratedFn:
        return self.fn


# noinspection PyPep8Naming
class execute_command:  # noqa: N801
    """
    In case you want to expose a method as worker task to the core, you can use this decorator.
    Annotate the method with the name of the task, as well as the filter attributes.
    You can execute the annotated method by executing `execute-command` on the core.
    The argument passed is pared and provided to this function.
    Please note: only tasks that matches the filter criteria are received by this function.

    @execute_command(name="cmd_name", filter={"cloud": ["aws"]})
    def call_name(self, resource: Json, args: List[str]) -> Json:
       pass
    """

    def __init__(self, name: str, filter: Optional[Dict[str, List[str]]] = None) -> None:
        self.name = name
        self.filter = filter or {}

    def __call__(self, fn: DecoratedFn) -> DecoratedFn:
        return _WorkerTaskDecorator(fn, self.name, self.filter, False)


# noinspection PyPep8Naming
class execute_command_on_resource:  # noqa: N801
    """
    See execute_command.

    This decorator will convert the incoming message to a resource object
    and a resulting object back to the json representation.

    @execute_command_on_resource(name="cmd_name", filter={"cloud": ["aws"]})
    def call_name(self, resource: BaseResource, args: List[str]) -> Optional[BaseResource]:
       pass
    """

    def __init__(self, name: str, filter: Optional[Dict[str, List[str]]] = None) -> None:
        self.name = name
        self.filter = filter or {}

    def __call__(self, fn: DecoratedFn) -> DecoratedFn:
        return _WorkerTaskDecorator(fn, self.name, self.filter, True)
