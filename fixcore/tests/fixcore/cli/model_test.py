from textwrap import dedent

import pytest

from fixcore.cli.cli import CLIService
from fixcore.cli.model import (
    CLIContext,
    AliasTemplate,
    AliasTemplateParameter,
    InfraAppAlias,
    InfraAppAliasParameter,
)
from fixcore.console_renderer import ConsoleRenderer, ConsoleColorSystem
from fixcore.user.model import AuthorizedUser, Permission


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
    assert CLIContext().render_console(tpl.help()) == dedent(
        """
        foo: does foes
        ```shell
        foo --a <value> --b <value>
        ```

        ## Parameters
        - `--a` [required]: some a
        - `--b` [default: bv]: some b

        ## Template
        ```shell
        > {{a}} | {{b}}
        ```

        ## Example
        ```shell
        # Executing this command
        > foo --a "test-a"
        # Will expand to this command
        > test-a | bv
        ```
        """
    )

    tpl_no_args = AliasTemplate(
        "bla",
        "does blas",
        "bla {{args}}",
        description="This is doing bla",
        args_description={"p1": "is doing awesome", "p2": "enables after burners"},
    )
    assert tpl_no_args.render({"args": "something"}) == "bla something"
    assert (
        CLIContext().render_console(tpl_no_args.help()).strip()
        == dedent(
            """
            bla: does blas
            ```shell
            bla  [p1] [p2]
            ```

            ## Parameters

            - `p1`: is doing awesome
            - `p2`: enables after burners

            This is doing bla
            """
        ).strip()
    )


def test_infra_app_alias() -> None:
    params = [
        InfraAppAliasParameter(
            name="param_a",
            help="some a",
            default=None,
        ),
        InfraAppAliasParameter(
            name="param_b",
            help="some b",
            default="default_b",
        ),
    ]
    alias = InfraAppAlias("foo", "does foes", "readme", params)
    assert alias.render({"args": "args_go_here"}) == "apps run foo args_go_here"
    assert alias.rendered_help(CLIContext()) == dedent(
        """
        foo: does foes
        ```shell
        foo --param-a <value> --param-b <value>
        ```

        readme
        ## Parameters
        - `--param-a` [required]: some a
        - `--param-b` [default: default_b]: some b"""
    )


@pytest.mark.asyncio
async def test_is_allowed(cli: CLIService) -> None:
    # no user provided
    res = (await cli.evaluate_cli_command("config show fix.core"))[0]
    assert res.is_allowed_to_execute() is False
    res = (await cli.evaluate_cli_command("search all"))[0]
    assert res.is_allowed_to_execute() is False
    # user with read access
    readonly = CLIContext(user=AuthorizedUser("test@test.de", {"readonly"}, {Permission.read}, True))
    res = (await cli.evaluate_cli_command("config show fix.core", context=readonly))[0]
    assert res.is_allowed_to_execute() is False
    res = (await cli.evaluate_cli_command("search all", context=readonly))[0]
    assert res.is_allowed_to_execute() is True
    # admin with all access
    admin = CLIContext(
        user=AuthorizedUser("test@test.de", {"admin"}, {Permission.read, Permission.write, Permission.admin}, True)
    )
    res = (await cli.evaluate_cli_command("config show fix.core", context=admin))[0]
    assert res.is_allowed_to_execute() is True
    res = (await cli.evaluate_cli_command("search all", context=admin))[0]
    assert res.is_allowed_to_execute() is True
