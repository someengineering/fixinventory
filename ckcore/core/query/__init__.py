from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, List, Optional

from core.query.model import Query
from core.types import Json


@dataclass
class Expandable:
    template: str  # the name of the template
    props: Json  # the properties to render this template


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Template:
    name: str  # the name of the template
    template: str  # the template string with placeholders


class QueryParser(ABC):
    @abstractmethod
    async def parse_query(self, to_parse: str) -> Query:
        """
        Parse given string into a query.
        The query might contain expandable sections.
        :param to_parse: the string to parse.
        :return: the parsed query.
        """


class TemplateExpander(QueryParser):
    @abstractmethod
    async def expand(self, maybe_expandable: str) -> Tuple[str, List[Expandable]]:
        """
        Expand the given string, which might contain expandable sections.
        All expandable sections get expanded and replaced in the string.
        If there are no expandable sections, the string is returned as is.

        If there are expandable sections, where the related template does not exist,
        an exception is thrown.

        :param maybe_expandable: a string which might contain expandable sections.
        :return: A string with all expandable sections expanded.
        :raises: NoSuchTemplateError if the related template of an expandable section does not exist.
        """

    @abstractmethod
    def render(self, template: str, properties: Json) -> str:
        """
        Render a given template with given properties.
        :param template: the template to render.
        :param properties: the properties used to define the template properties.
        :return: the fully rendered string without any template parameters.
        """

    @abstractmethod
    async def put_template(self, template: Template) -> None:
        """
        Put a named template to the template library.
        :param template: the template to put.
        :return: None.
        """

    @abstractmethod
    async def delete_template(self, name: str) -> None:
        """
        Delete a with given name from the template library.
        :param name: the name of the template to delete.
        :return: None.
        """

    @abstractmethod
    async def get_template(self, name: str) -> Optional[Template]:
        """
        Return the template with the given name.
        :param name: the name of the template.
        :return: the template with the given name if the template exists otherwise None.
        """

    @abstractmethod
    async def list_templates(self) -> List[Template]:
        """
        List all available templates in the system.
        :return: all templates in the system.
        """
