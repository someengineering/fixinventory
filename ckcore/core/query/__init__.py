from abc import ABC, abstractmethod

from core.query.model import Query


class QueryParser(ABC):
    """
    A query parser is able to parse a simple string into a query.
    """

    @abstractmethod
    async def parse_query(self, to_parse: str) -> Query:
        """
        Parse given string into a query.
        The query might contain expandable sections.
        :param to_parse: the string to parse.
        :return: the parsed query.
        """
