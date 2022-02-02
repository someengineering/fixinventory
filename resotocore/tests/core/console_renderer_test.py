from concurrent.futures import ThreadPoolExecutor

from rich.text import Text
from core.console_renderer import ConsoleColorSystem, ConsoleRenderer


def test_color_system() -> None:
    assert ConsoleColorSystem.monochrome.rich_color_system is None
    assert ConsoleColorSystem.eight_bit.rich_color_system is "256"
    assert ConsoleColorSystem.truecolor.rich_color_system is "truecolor"
    assert ConsoleColorSystem.legacy_windows.rich_color_system is "windows"


def test_from_name() -> None:
    for system in ConsoleColorSystem:
        assert ConsoleColorSystem.from_name(system.name) == system


def test_renderer_is_thread_safe() -> None:
    element = Text("some", "blue").append(Text("=", "dim").append("23", "green"))
    expected = ConsoleRenderer.renderer(color_system=ConsoleColorSystem.standard).render(element)

    def render() -> None:
        assert ConsoleRenderer.renderer(color_system=ConsoleColorSystem.standard).render(element) == expected

    with ThreadPoolExecutor(3) as pool:
        for n in range(0, 1000):
            pool.submit(render)

    assert len(ConsoleRenderer.console_pool.consoles) <= 3
