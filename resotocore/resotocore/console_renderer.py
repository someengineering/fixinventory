from __future__ import annotations

from collections import deque, defaultdict
from contextlib import contextmanager
from attrs import define
from enum import Enum
from functools import lru_cache
from typing import Optional, Union, Literal, Dict, Generator, ClassVar

from rich.console import Console
from rich.default_styles import DEFAULT_STYLES
from rich.jupyter import JupyterMixin
from rich.markdown import Markdown
from rich.theme import Theme


class ConsoleColorSystem(Enum):
    monochrome = 1
    standard = 2
    eight_bit = 3
    truecolor = 4
    legacy_windows = 5

    @staticmethod
    def from_name(name: str) -> ConsoleColorSystem:
        return ConsoleColorSystem[name.lower()]

    @property
    def rich_color_system(
        self,
    ) -> Optional[Literal["auto", "standard", "256", "truecolor", "windows"]]:
        if self == ConsoleColorSystem.monochrome:
            return None
        elif self == ConsoleColorSystem.eight_bit:
            return "256"
        elif self == ConsoleColorSystem.truecolor:
            return "truecolor"
        elif self == ConsoleColorSystem.standard:
            return "standard"
        elif self == ConsoleColorSystem.legacy_windows:
            return "windows"
        else:
            raise ValueError(f"No rich color system for {self}")


# This style is used in all consoles
ResotoTheme = Theme(DEFAULT_STYLES)


class ConsolePool:
    """
    Console implementation is not thread safe.
    In order to safely access console, a pool of consoles is used.
    A console can not be used concurrently: hence we maintain a pool of consoles to grab and reuse.
    Note: with and height of the pooled consoles have to be set explicitly before they are used.
    """

    def __init__(self) -> None:
        self.consoles: Dict[ConsoleColorSystem, deque[Console]] = defaultdict(deque)

    @contextmanager
    def with_console(self, system: ConsoleColorSystem) -> Generator[Console, None, None]:
        try:
            console = self.consoles[system].pop()
        except IndexError:
            console = Console(
                color_system=system.rich_color_system,
                force_terminal=True,
                force_interactive=False,
                width=120,
                height=25,
                no_color=system == ConsoleColorSystem.monochrome,
                legacy_windows=system == ConsoleColorSystem.legacy_windows,
                theme=ResotoTheme,
            )
        yield console
        self.consoles[system].append(console)


@define
class ConsoleRenderer:
    width: Optional[int] = None
    height: Optional[int] = None
    color_system: Optional[ConsoleColorSystem] = None
    terminal: Optional[bool] = None

    # Use this object pool to maintain used consoles
    console_pool: ClassVar[ConsolePool] = ConsolePool()

    def render(self, element: Union[str, JupyterMixin]) -> str:
        # Code blocks are rendered via pygments, which can be styled using themes.
        # For a list of styles see: https://stylishthemes.github.io/Syntax-Themes/pygments/
        # The default uses monokai, which can be hard to read on standard terminal devices.
        # See: https://github.com/someengineering/resoto/issues/652 for problems with monokai.
        to_render = Markdown(element, code_theme="native") if isinstance(element, str) else element
        # get a console with the correct color system
        cs = self.color_system
        system = cs if cs else (ConsoleColorSystem.standard if self.terminal else ConsoleColorSystem.monochrome)
        with ConsoleRenderer.console_pool.with_console(system) as console:
            # explicitly set the width and height here
            console.width = self.width if self.width else 80
            console.height = self.height if self.height else 25
            # capture the output of this console
            with console.capture() as capture:
                console.print(to_render)
            return capture.get()

    @staticmethod
    @lru_cache
    def default_renderer() -> ConsoleRenderer:
        # Output is created in a way, that it can be displayed on any terminal
        return ConsoleRenderer(80, 25, ConsoleColorSystem.monochrome)
