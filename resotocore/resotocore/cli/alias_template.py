from typing import Optional, List, Dict, Union, Any
from attrs import define, field
from operator import attrgetter
from textwrap import dedent

from resotocore.types import Json, JsonElement
from resotocore.query.template_expander import render_template
from resotocore.core_config import AliasTemplateConfig, AliasTemplateParameterConfig


@define
class ArgInfo:
    # If the argument has a name. It is quite common that arguments do not have a name
    # but are expected at some position.
    # Example: `count <kind>`: kind is the argument at position 1 without a name
    name: Optional[str] = None
    # Defines if this argument expects a value.
    # Some arguments are only flags, while others expect a value.
    # Example: `--compress` is a flag without value
    # Example: `--count <kind>` is an argument with value
    expects_value: bool = False
    # If the value has to be picked from a list of values (enumeration).
    # Example: `--format svg|png|jpg`
    possible_values: List[str] = field(factory=list)
    # If this argument is allowed to be specified multiple times
    can_occur_multiple_times: bool = False
    # Give a type hint for the argument value.
    # Allowed values are:
    # - `file`: the argument expects a file path
    # - `kind`: the argument expects a kind in the model
    # - `property`: the argument expects a property in the model
    # - `command`: the argument expects a command on the cli
    # - `event`: the event handled or emitted by the task handler
    # - `search`: the argument expects a search string
    value_hint: Optional[str] = None
    # Help text of the argument option.
    help_text: Optional[str] = None
    # If multiple options share the same group, only one of them can be selected.
    # Use groups if you have multiple options, where only one is allowed to be selected.s
    option_group: Optional[str] = None


# mypy does not support recursive type aliases: define 3 levels as maximum here
ArgsInfo = Union[
    Dict[str, Union[Dict[str, Union[Dict[str, Union[Any, List[ArgInfo]]], List[ArgInfo]]], List[ArgInfo]]],
    List[ArgInfo],
]


@define(order=True, hash=True, frozen=True)
class AliasTemplateParameter:
    name: str
    description: str
    default: Optional[JsonElement] = None

    def example_value(self) -> JsonElement:
        return self.default if self.default else f"test_{self.name}"

    @property
    def arg_name(self) -> str:
        return "--" + self.name.replace("_", "-")


# pylint: disable=not-an-iterable
@define(order=True, hash=True, frozen=True)
class AliasTemplate:
    name: str
    info: str
    template: str
    parameters: List[AliasTemplateParameter] = field(factory=list)
    description: Optional[str] = None
    # only use args_description if the template does not use explicit parameters
    args_description: Dict[str, str] = field(factory=dict)
    allowed_in_source_position: bool = False

    def render(self, props: Json) -> str:
        return render_template(self.template, props)

    def args_info(self) -> ArgsInfo:
        args_desc = [ArgInfo(name, expects_value=True, help_text=desc) for name, desc in self.args_description.items()]
        param = [
            ArgInfo(
                p.arg_name,
                expects_value=True,
                help_text=f"[{'required' if p.default is None else 'optional'}] {p.description}",
            )
            for p in sorted(self.parameters, key=lambda p: p.default is not None)  # required parameters first
        ]
        return args_desc + param

    def help_with_params(self) -> str:
        args = " ".join(f"{arg.arg_name} <value>" for arg in self.parameters)

        def param_info(p: AliasTemplateParameter) -> str:
            default = f" [default: {p.default}]" if p.default else ""
            return f"- `{p.name}`{default}: {p.description}"

        indent = "            "
        arg_info = f"\n{indent}".join(param_info(arg) for arg in sorted(self.parameters, key=attrgetter("name")))
        minimal = " ".join(f'{p.arg_name} "{p.example_value()}"' for p in self.parameters if p.default is None)
        desc = ""
        if self.description:
            for line in self.description.splitlines():
                desc += f"\n{indent}{line}"
        return dedent(
            f"""
            {self.name}: {self.info}
            ```shell
            {self.name} {args}
            ```
            {desc}
            ## Parameters
            {arg_info}

            ## Template
            ```shell
            > {self.template}
            ```

            ## Example
            ```shell
            # Executing this alias template
            > {self.name} {minimal}
            # Will expand to this command
            > {self.render({p.name: p.example_value() for p in self.parameters})}
            ```
            """
        )

    def help_no_params_args(self) -> str:
        args = ""
        args_info = ""
        for arg_name, arg_description in self.args_description.items():
            args += f" [{arg_name}]"
            args_info += f"\n- `{arg_name}`: {arg_description}"

        args_info = args_info or ("<args>" if "{args}" in self.template else "")
        return (
            f"{self.name}: {self.info}\n```shell\n{self.name} {args}\n```\n\n"
            f"## Parameters\n{args_info}\n\n{self.description}\n\n"
        )

    def help(self) -> str:
        return self.help_with_params() if self.parameters else self.help_no_params_args()

    @staticmethod
    def from_config(cfg: AliasTemplateConfig) -> "AliasTemplate":
        def arg(p: AliasTemplateParameterConfig) -> AliasTemplateParameter:
            return AliasTemplateParameter(p.name, p.description, p.default)

        return AliasTemplate(
            name=cfg.name,
            info=cfg.info,
            template=cfg.template,
            parameters=[arg(a) for a in cfg.parameters],
            description=cfg.description,
            allowed_in_source_position=cfg.allowed_in_source_position or False,
        )
