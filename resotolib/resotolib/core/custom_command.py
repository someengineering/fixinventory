from typing import Any, Dict, List, Type, Optional

from resotolib.types import DecoratedFn

definitions = "__task_definitions"


class CommandDefinition:
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
    The definition is used to register a custom command at the core, when the worker connects.
    The custom command can be executed with the provided name.
    Note: any existing command or alias takes precedence over the custom command.

    The expected signature of the function is this:

    def some_name(self, config: Config, js: Json, args: List[str]) -> JsonElement:

    Notes on the signature:
    - the json is the node section of the core task data.
    - the args contains the list of arguments provided by the user.
    - the function returns json. None is a valid json element.

    :param name: the name of the command
    :param info: a short description of the command
    :param args_description: a dictionary of argument names and their description
    :param description: a longer description of the command
    :param expect_node_result: if true, the returned json is a resource and the current node in the db will be updated.
    :param allowed_on_kind: if set, the command will only be executed on resources of this kind
    :param filter: filter attributes as selector for this command.
           Multiple workers might register the same command on the same resource with different filters.
           Based on the resource the task is delegated to the worker with the matching filter.
    :return: the decorated function that will be registered as worker task.
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
        return CommandDefinition(
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

    The expected signature of the function is this:

    def some_name(
        self, config: Config, resource: Optional[BaseResource], args: List[str]
    ) -> Union[JsonElement, BaseResource]:

    Notes on the signature:
    - the resource is marked as optional. In case the command is executed in source position, no resource is provided.
    - the args contains the list of arguments provided by the user.
    - the function can decide to return either a json element or a resource. None is a valid json element.

    :param name: the name of the command
    :param info: a short description of the command
    :param args_description: a dictionary of argument names and their description
    :param description: a longer description of the command
    :param expect_node_result: if true, the returned resource will update the current node in the database.
    :param allowed_on_kind: if set, the command will only be executed on resources of this kind
    :param filter: filter attributes as selector for this command.
           Multiple workers might register the same command on the same resource with different filters.
           Based on the resource the task is delegated to the worker with the matching filter.
    :return: the decorated function that will be registered as worker task.
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
        return CommandDefinition(
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


def command_definitions(clazz: Type[Any]) -> List[CommandDefinition]:
    return getattr(clazz, definitions, [])
