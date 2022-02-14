class CoreException(Exception):
    pass


class ClientError(Exception):
    """
    Mark error as something the client caused.
    """


class NotFoundError(ClientError):
    """
    Mark error as something that could not be found.
    """


class ServerError(Exception):
    """
    Mark error as something the server caused.
    """


class RequiredDependencyMissingError(ServerError):
    """
    Required downstream system is not available or not available in correct version.
    """


class DatabaseError(CoreException):
    """
    Base for all database exceptions.
    """


class QueryTookToLongError(DatabaseError, ClientError):
    pass


class InvalidBatchUpdate(CoreException, ClientError):
    def __init__(self) -> None:
        super().__init__("The same batch can not update the same subgraph or any parent node!")


class ConflictingChangeInProgress(CoreException, ClientError):
    def __init__(self, other_change_id: str):
        super().__init__(f"Conflicting change in progress: {other_change_id}!")
        self.other_change_id = other_change_id


class OptimisticLockingFailed(CoreException, ClientError):
    def __init__(self, uid: str, current_revision: str, read_revision: str) -> None:
        super().__init__(
            f"Node {uid}: The record to update has been changed since it was read!"
            + f"Current revision: {current_revision} Read revision: {read_revision}"
        )
        self.uid = uid
        self.current_revision = current_revision
        self.read_revision = read_revision


class NoSuchGraph(CoreException, NotFoundError):
    def __init__(self, graph: str):
        super().__init__(f"No graph with this name {graph}")
        self.graph = graph


class NoSuchChangeError(CoreException, NotFoundError):
    def __init__(self, change_id: str):
        super().__init__(f"No batch with given id {change_id}")
        self.change_id = change_id


class ImportAborted(CoreException, ClientError):
    pass


class CLIParseError(CoreException, ClientError):
    pass


class CLIExecutionError(CoreException, ClientError):
    pass


class ParseError(CoreException, ClientError):
    pass


class NoSuchTemplateError(CoreException, NotFoundError):
    def __init__(self, template: str):
        super().__init__(f"Template {template} does not exist.")
        self.template = template
