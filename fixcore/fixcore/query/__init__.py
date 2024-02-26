from abc import ABC, abstractmethod
from typing import Optional, Dict

from fixcore.query.model import Query


class QueryParser(ABC):
    """
    A query parser is able to parse a simple string into a query.
    """

    @abstractmethod
    async def parse_query(
        self,
        to_parse: str,
        on_section: Optional[str],
        *,
        omit_section_expansion: bool = False,
        env: Optional[Dict[str, str]] = None,
    ) -> Query:
        """
        Parse given string into a query.
        The query might contain expandable sections.
        :param to_parse: the string to parse.
        :param on_section: interpret the query relative to given section.
               If the section is none, all paths are considered absolute.
        :param omit_section_expansion: if this flag is true, the query is not interpreted relative to section.
        :param env: optional environment variables to use.
        :return: the parsed query.
        """
