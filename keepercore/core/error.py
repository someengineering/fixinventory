class CoreException(Exception):
    pass


class NotFoundError(Exception):
    pass


class DomainError(Exception):
    pass


class DatabaseError(DomainError):
    pass


class InvalidBatchUpdate(DatabaseError):
    def __init__(self) -> None:
        super().__init__("The same batch can not update the same subgraph or any parent node!")


class ConflictingChangeInProgress(DatabaseError):
    def __init__(self, other_change_id: str):
        super().__init__(f"Conflicting change in progress: {other_change_id}!")
        self.other_change_id = other_change_id


class NoSuchGraph(DatabaseError, NotFoundError):
    def __init__(self, graph: str):
        super().__init__(f"No graph with this name {graph}")
        self.graph = graph


class NoSuchBatchError(DatabaseError, NotFoundError):
    def __init__(self, change_id: str):
        super().__init__(f"No batch with given id {change_id}")
        self.change_id = change_id


class CLIParseError(DomainError):
    pass


class ParseError(DomainError):
    pass
