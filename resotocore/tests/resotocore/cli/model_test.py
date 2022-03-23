from textwrap import dedent

from resotocore.cli.model import CLIContext, AliasTemplate, AliasTemplateParameter
from resotocore.console_renderer import ConsoleRenderer, ConsoleColorSystem


def test_format() -> None:
    context = CLIContext()
    fn = context.formatter("foo={foo} and bla={bla}: {bar}")
    assert fn({}) == "foo=null and bla=null: null"
    assert fn({"foo": 1, "bla": 2, "bar": 3}) == "foo=1 and bla=2: 3"


def test_context_format() -> None:
    context = CLIContext()
    fn, vs = context.formatter_with_variables("foo={foo} and bla={bla}: {bar}")
    assert vs == {"foo", "bla", "bar"}
    assert fn({}) == "foo=null and bla=null: null"
    assert fn({"foo": 1, "bla": 2, "bar": 3}) == "foo=1 and bla=2: 3"


def test_supports_color() -> None:
    assert not CLIContext().supports_color()
    assert not CLIContext(console_renderer=ConsoleRenderer()).supports_color()
    assert not CLIContext(console_renderer=ConsoleRenderer(color_system=ConsoleColorSystem.monochrome)).supports_color()
    assert CLIContext(console_renderer=ConsoleRenderer(color_system=ConsoleColorSystem.standard)).supports_color()
    assert CLIContext(console_renderer=ConsoleRenderer(color_system=ConsoleColorSystem.eight_bit)).supports_color()
    assert CLIContext(console_renderer=ConsoleRenderer(color_system=ConsoleColorSystem.truecolor)).supports_color()


def test_alias_template() -> None:
    params = [AliasTemplateParameter("a", "some a"), AliasTemplateParameter("b", "some b", "bv")]
    tpl = AliasTemplate("foo", "does foes", "{{a}} | {{b}}", params)
    assert tpl.render({"a": "test", "b": "bla"}) == "test | bla"
    assert tpl.rendered_help(CLIContext()) == dedent(
        """
        foo: does foes
        ```shell
        foo a=<value>, b=<value>
        ```
        ## Parameters
        - `a`: some a
        - `b` [default: bv]: some b

        ## Template
        ```shell
        > {{a}} | {{b}}
        ```

        ## Example
        ```shell
        # Executing this alias template
        > foo a="test_a"
        # Will expand to this command
        > test_a | bv
        ```
        """
    )
