from typing import Any, Dict, List, Type, Optional

from resotolib.types import DecoratedFn

definitions = "__task_definitions"


class WorkerTaskDecorator:
    """
    A final decorator is called by the interpreter once after the class is defined.
    (Not the case for decorators with attributes)
    This decorator will maintain all decorated methods on the class side.
    Use task_definitions(clazz) to get all task definitions of a specific class.
    """

    def __init__(
        self,
        fn: DecoratedFn,
        name: str,
        info: str,
        args_description: Dict[str, str],
        description: str,
        expect_node_result: bool = False,
        expect_resource: bool = False,
        allowed_on_kind: Optional[str] = None,
        filter: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.fn = fn
        self.name = name
        self.info = info
        self.args_description = args_description
        self.description = description
        self.expect_resource = expect_resource
        self.expect_node_result = expect_node_result
        self.allowed_on_kind = allowed_on_kind
        self.filter = filter

    def __set_name__(self, owner, name):
        # store this definition on the owners side (class)
        if getattr(owner, definitions, None) is None:
            setattr(owner, definitions, [])
        getattr(owner, definitions).append(self)
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

    def __init__(
        self,
        name: str,
        info: str,
        args_description: Dict[str, str],
        description: str,
        expect_node_result: bool = False,
        allowed_on_kind: Optional[str] = None,
        filter: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.name = name
        self.info = info
        self.args_description = args_description
        self.description = description
        self.expect_node_result = expect_node_result
        self.allowed_on_kind = allowed_on_kind
        self.filter = filter or {}

    def __call__(self, fn: DecoratedFn) -> DecoratedFn:
        return WorkerTaskDecorator(
            fn,
            name=self.name,
            info=self.info,
            args_description=self.args_description,
            description=self.description,
            expect_node_result=self.expect_node_result,
            expect_resource=False,
            allowed_on_kind=self.allowed_on_kind,
            filter=self.filter,
        )


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

    def __init__(
        self,
        name: str,
        info: str,
        args_description: Dict[str, str],
        description: str,
        expect_node_result: bool = False,
        allowed_on_kind: Optional[str] = None,
        filter: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.name = name
        self.info = info
        self.args_description = args_description
        self.description = description
        self.expect_node_result = expect_node_result
        self.allowed_on_kind = allowed_on_kind
        self.filter = filter or {}

    def __call__(self, fn: DecoratedFn) -> DecoratedFn:
        return WorkerTaskDecorator(
            fn,
            name=self.name,
            info=self.info,
            args_description=self.args_description,
            description=self.description,
            expect_node_result=self.expect_node_result,
            expect_resource=True,
            allowed_on_kind=self.allowed_on_kind,
            filter=self.filter,
        )


def task_definitions(clazz: Type[Any]) -> List[WorkerTaskDecorator]:
    return getattr(clazz, definitions, [])
