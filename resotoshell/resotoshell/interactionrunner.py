from __future__ import annotations

import json
import os
import re
import time
from abc import ABC, abstractmethod
from enum import Enum, unique
from functools import reduce
from typing import Optional, List, Dict, Any, Tuple, Union, Callable, Sized

from attr import define, field
from cattrs import Converter, gen
from resotoclient import ResotoClient

from resotolib.logger import log
from resotolib.types import Json, JsonElement
from resotoshell.dialogs import CancelledError, ConversationFinishedError, AbortError, progress_dialog
from resotoshell.dialogs import (
    input_dialog,
    checkboxlist_dialog,
    button_dialog,
    yes_no_dialog,
    radiolist_dialog,
    message_dialog,
)


def value_in_path(js: Json, path: str) -> Optional[JsonElement]:
    parts = path.split(".")
    res = js
    for part in parts:
        if isinstance(js, dict):
            res = res.get(part)  # type: ignore
        else:
            return None
    return res


@unique
class JsonAction(Enum):
    replace = "replace"
    merge = "merge"


@define
class ActionResult:
    # None in case the root should be replaced, otherwise the path in a dict
    path: Optional[str]
    # which action to perform
    action: JsonAction
    # The value to replace
    patch: JsonElement

    def render(self, js: Optional[Json]) -> Json:
        parts = self.path.split(".") if self.path else []
        if len(parts) == 0 or js is None:
            return self.patch  # type: ignore
        elif len(parts) == 1:
            js[self.path] = self.patch  # type: ignore
            return js
        else:
            res_js = js
            for path in parts[:-1]:
                outer = js
                js = outer.get(path)
                if not isinstance(js, dict):
                    js = {}
                    outer[path] = js
                if self.action == JsonAction.replace:
                    js[parts[-1]] = self.patch
                elif self.action == JsonAction.merge:
                    if isinstance(self.patch, dict):
                        js[parts[-1]] = {**js.get(parts[-1], {}), **self.patch}
                    elif isinstance(self.patch, list):
                        js[parts[-1]] = list({*js.get(parts[-1], []), *self.patch})
                    else:
                        raise AttributeError(f"Don't know how to merge this value: {js}")
                else:
                    raise AttributeError(f"Don't know how to handle this action: {self.action}")

            return res_js


@define
class PatchStatic:
    path: str
    value: JsonElement
    action: JsonAction = JsonAction.replace


@define
class PatchValueAction:
    path: str
    value_template: str
    action: JsonAction = JsonAction.replace
    default: JsonElement = None

    def render(self, value: Union[None, str, List[str]]) -> List[ActionResult]:
        def single(v: str) -> JsonElement:
            replaced = self.value_template.replace("@value@", str(v) if not isinstance(value, str) else value)
            return json.loads(replaced)  # type: ignore

        if value is None:
            js = None
        else:
            js = [single(v) for v in value] if isinstance(value, list) else single(value)
        return [ActionResult(self.path, self.action, js)]


@define
class OnlyIf(ABC):
    @abstractmethod
    def is_true(self, js: Json) -> bool:
        pass

    @staticmethod
    def from_json_hook(cv: Converter) -> Callable[[Json, Any], OnlyIf]:
        defined = gen.make_dict_structure_fn(OnlyIfDefined, cv)
        undefined = gen.make_dict_structure_fn(OnlyIfUndefined, cv)
        value = gen.make_dict_structure_fn(OnlyIfValue, cv)
        if_len = gen.make_dict_structure_fn(OnlyIfLen, cv)

        def from_json(js: Json, other: Any) -> OnlyIf:
            if js.get("kind") == "defined":
                return defined(js, other)
            elif js.get("kind") == "undefined":
                return undefined(js, other)
            elif js.get("kind") == "value":
                return value(js, other)
            elif js.get("kind") == "len":
                return if_len(js, other)
            else:
                raise AttributeError(f"Don't know how to handle this step: {js}")

        return from_json


@define
class OnlyIfDefined(OnlyIf):
    path: str

    def is_true(self, js: Json) -> bool:
        return value_in_path(js, self.path) is not None


@define
class OnlyIfLen(OnlyIf):
    path: str
    op: str
    value: int

    def is_true(self, js: Json) -> bool:
        val = value_in_path(js, self.path)
        ll = len(val) if isinstance(val, Sized) else 0
        if self.op in ("=", "=="):
            return ll == self.value
        elif self.op == ">":
            return ll > self.value
        elif self.op == ">=":
            return ll >= self.value
        elif self.op == "<":
            return ll < self.value
        elif self.op == "<=":
            return ll <= self.value
        else:
            raise AttributeError(f"Don't know how to handle this operator: {self.op}")


@define
class OnlyIfValue(OnlyIf):
    path: str
    value: JsonElement

    def is_true(self, js: Json) -> bool:
        return value_in_path(js, self.path) == self.value


@define
class OnlyIfUndefined(OnlyIf):
    path: str

    def is_true(self, js: Json) -> bool:
        return value_in_path(js, self.path) is None


@define
class ExecuteCommand(ABC):
    def execute(self, cv: Conversation) -> JsonElement:
        pass

    @staticmethod
    def from_json_hook(cv: Converter) -> Callable[[Json, Any], ExecuteCommand]:
        execute = gen.make_dict_structure_fn(ExecuteCLICommand, cv)
        put_config = gen.make_dict_structure_fn(PutConfiguration, cv)

        def from_json(js: Json, other: Any) -> ExecuteCommand:
            if js.get("kind") == "execute":
                return execute(js, other)
            elif js.get("kind") == "put_config":
                return put_config(js, other)
            else:
                raise AttributeError(f"Don't know how to handle this step: {js}")

        return from_json


@define
class ExecuteCLICommand(ExecuteCommand):
    command: str

    def execute(self, cv: Conversation) -> JsonElement:
        return list(cv.client.cli_execute(self.command))


@define
class PutConfiguration(ExecuteCommand):
    def execute(self, cv: Conversation) -> JsonElement:
        return cv.client.put_config(cv.interaction.config, cv.json_document)  # type: ignore


@define
class Conversation:
    interaction: Interaction
    json_document: Json
    client: ResotoClient
    steps: List[Tuple[InteractionStep, List[ActionResult]]] = field(factory=list)

    def apply(self, step: InteractionStep, actions: List[ActionResult]) -> List[ActionResult]:
        """
        Apply the step and reflect the related changes in the json document.
        """
        update = self.json_document.copy()
        for action in actions:
            update = action.render(update)
        self.json_document = update
        self.steps.append((step, actions))
        for cmd in step.commands:
            exec_result = cmd.execute(self)
            log.debug(f"Result of command {cmd} is {exec_result}")

        return actions

    def skip(self, step: InteractionStep) -> None:
        """
        Skip the step and set the related patches to the default value.
        This involves all transitives steps that are skipped with the current step.
        """

        def transitive_steps(s: InteractionStep) -> List[InteractionStep]:
            si: List[InteractionStep] = [s]
            if isinstance(s, (InteractionInput, InteractionInfo, SubInteraction)):
                return si
            elif isinstance(s, InteractionSequence):
                return si + [b for a in s.steps for b in transitive_steps(a)]
            elif isinstance(s, InteractionDecision):
                return si + [b for a in s.step_options.values() for b in transitive_steps(a)]
            else:
                raise AttributeError(f"Don't know how to handle this step: {type(s)}")

        # apply all skipped input steps with value None
        for ts in transitive_steps(step):
            if isinstance(ts, InteractionInput):
                self.apply(ts, [ActionResult(ts.action.path, JsonAction.replace, ts.action.default)])
            elif isinstance(ts, SubInteraction):
                # set an empty array for the sub interaction path
                self.apply(ts, [ActionResult(ts.path, JsonAction.replace, [])])

    def should_execute(self, step: InteractionStep) -> bool:
        return all(only_if.is_true(self.json_document) for only_if in (step.only_if or []))


@define(kw_only=True)
class InteractionStep(ABC):
    name: str
    help: str
    patches: List[PatchStatic] = field(factory=list)
    id: Optional[str] = None
    only_if: Optional[List[OnlyIf]] = None
    is_terminal: bool = False
    links: Optional[Dict[str, str]] = None  # Title -> URL
    commands: List[ExecuteCommand] = field(factory=list)

    @property
    def message(self) -> str:
        result = self.help
        if self.links:
            result += "\n\n"
            for title, url in self.links.items():
                result += f"{title}: {url}\n"
        return result

    @abstractmethod
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        return [ActionResult(sp.path, sp.action, sp.value) for sp in self.patches]

    def execute_step(self, conversation: Conversation) -> List[ActionResult]:
        if conversation.should_execute(self):
            actions = self.execute(conversation)
            result = conversation.apply(self, actions)
            if self.is_terminal:
                raise ConversationFinishedError()  # in case the step is terminal, we skip whatever comes next
            return result
        else:
            conversation.skip(self)
            return []

    @staticmethod
    def from_json_hook(cv: Converter) -> Callable[[Json, Any], InteractionStep]:
        info = gen.make_dict_structure_fn(InteractionInfo, cv)
        iinput = gen.make_dict_structure_fn(InteractionInput, cv)
        sub = gen.make_dict_structure_fn(SubInteraction, cv)
        seq = gen.make_dict_structure_fn(InteractionSequence, cv)
        decision = gen.make_dict_structure_fn(InteractionDecision, cv)
        progress = gen.make_dict_structure_fn(InteractionProgress, cv)

        def from_json(js: Json, other: Any) -> InteractionStep:
            if js.get("kind") == "info":
                return info(js, other)
            elif js.get("kind") == "input":
                return iinput(js, other)
            elif js.get("kind") == "sub_interaction":
                return sub(js, other)
            elif js.get("kind") == "seq":
                return seq(js, other)
            elif js.get("kind") == "decision":
                return decision(js, other)
            elif js.get("kind") == "progress":
                return progress(js, other)
            else:
                raise AttributeError(f"Don't know how to handle this step: {js}")

        return from_json


class InteractionProgress(InteractionStep):
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        def update_progress(progress: Callable[[int], None], text: Callable[[str], None]) -> None:
            start = int(time.time())
            last_check: float = start
            text("Collecting data... hang tight!")
            while True:
                now = time.time()
                # 10 ticks / second
                progress(int((now - start) * 10) % 99)
                # only check every 1 second
                if (now - last_check) > 1:
                    last_check = now
                    running = list(conversation.client.cli_execute("workflows running"))
                    if not running:
                        progress(100)
                        text("Collecting data is done!")
                        break
                time.sleep(0.1)

        progress_dialog(self.name, self.message, update_progress).run()

        return []


@define(kw_only=True)
class InteractionInfo(InteractionStep):
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        result = super().execute(conversation)
        message_dialog(title=self.name, text=self.message).run()
        return result


@define(kw_only=True)
class InteractionInput(InteractionStep):
    action: PatchValueAction
    # options to display -> value to use
    value_options: Optional[Dict[str, str]] = None
    # if this value is set, the input is splitted by this character and the result becomes a list
    split_result_by: Optional[str] = None
    # if this field displays a password
    password: bool = False
    # in case the value to enter should conform to a specific type
    expected_type: Optional[str] = None

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        result: Union[None, str, List[str]] = None
        if self.value_options is None:  # show simple text input field
            existing = value_in_path(conversation.json_document, self.action.path)
            ex_str = ", ".join(existing) if isinstance(existing, list) else "" if existing is None else str(existing)
            result = input_dialog(title=self.name, text=self.message, field_text=ex_str, password=self.password).run()
        else:
            width = reduce(lambda a, b: a + b, [len(a) for a in self.value_options])

            if width < 50:
                result = button_dialog(
                    title=self.name, text=self.message, buttons=[(k, v) for k, v in self.value_options.items()]
                ).run()
            else:
                result = radiolist_dialog(
                    title=self.name, text=self.message, values=[(v, k) for k, v in self.value_options.items()]
                ).run()
        if result is None:
            raise CancelledError()
        if split := self.split_result_by:
            result = re.split("\\s*" + re.escape(split) + "\\s*", result)
        else:
            result = None if result == "" else result  # interpret empty string as None
        return base + self.action.render(result)


@define(kw_only=True)
class InteractionDecision(InteractionStep):
    select_multiple: bool = False
    # value to display -> wizard step to use
    step_options: Dict[str, InteractionStepUnion]

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        while True:
            step_names = []
            if self.select_multiple:
                step_names = checkboxlist_dialog(
                    title=self.name, text=self.message, values=[(k, k) for k in self.step_options]
                ).run()
            else:
                step_names = [
                    radiolist_dialog(
                        title=self.name, text=self.message, values=[(k, k) for k in self.step_options]
                    ).run()
                ]

            # safety check for the selection
            if step_names is None or any(s is None for s in step_names):
                raise CancelledError()

            try:
                actions = []
                for name, step in self.step_options.items():
                    if name in step_names:
                        actions.extend(step.execute_step(conversation))
                    else:
                        conversation.skip(step)
                return base + actions
            except CancelledError:
                pass  # user cancelled the sub dialog, represent the decision


@define(kw_only=True)
class SubInteraction(InteractionStep):
    path: str
    steps: List[InteractionStepUnion]
    patch_action: JsonAction = field(default=JsonAction.replace)

    def iterate(self, conversation: Conversation) -> Json:
        js: Optional[Json] = {}
        for step in self.steps:
            # we can not use the execute_step method here, since the result would be applied directly
            if conversation.should_execute(step):
                for result in step.execute(conversation):
                    js = result.render(js)
        return js or {}

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        result_list = []
        flag = True
        while flag:
            try:
                result_list.append(self.iterate(conversation))
            except CancelledError:
                pass
            # ask the user if he wants to do another
            flag = yes_no_dialog(title=self.name, text=self.message).run()
        return base + [ActionResult(self.path, self.patch_action, result_list)]


@define(kw_only=True)
class InteractionSequence(InteractionStep):
    steps: List[InteractionStepUnion]

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        return base + [res for step in self.steps for res in step.execute_step(conversation)]


InteractionStepUnion = Union[
    InteractionInfo, InteractionInput, InteractionDecision, SubInteraction, InteractionSequence
]

converter = Converter()
converter.register_structure_hook(JsonElement, lambda a, x: a)  # type: ignore
converter.register_structure_hook(OnlyIf, OnlyIf.from_json_hook(converter))
converter.register_structure_hook(ExecuteCommand, ExecuteCommand.from_json_hook(converter))
converter.register_structure_hook(InteractionStep, InteractionStep.from_json_hook(converter))


@define(kw_only=True)
class Interaction:
    config: str
    steps: List[InteractionStepUnion]

    @staticmethod
    def from_json(js: Json) -> Interaction:
        return converter.structure(js, Interaction)


class InteractionRunner:
    def __init__(self, interaction: Interaction, client: ResotoClient):
        self.interaction = interaction
        self.client = client

    def interact(self, original: Json) -> Conversation:
        count = 0
        conversation = Conversation(self.interaction, original, self.client)

        while count < len(self.interaction.steps):
            step = self.interaction.steps[count]
            try:
                step.execute_step(conversation)
                count += 1
            except CancelledError:
                # user cancelled this step, go back, if not already at the beginning
                if count == 0:
                    raise
                count -= 1
            except ConversationFinishedError:
                # terminal step reached for the current communication path. move on.
                count += 1
        return conversation

    def run(self) -> None:
        try:
            orig = self.client.config(self.interaction.config)
        except Exception:
            log.info(f"Configuration {self.interaction.config} not found. Give up.")
            message_dialog(
                "Error",
                f"Can not find the configuration {self.interaction.config}.\n"
                "This usually indicates, that the installation has not been completed correctly.\n"
                "In case you removed a configuration manually, you need to restart the respective component,\n"
                "so a default configuration will be created.\n\n",
                "Please try again later, when this issue is resolved.",
            ).run()
            return

        try:
            self.interact(orig)
        except (CancelledError, AbortError):
            log.info("User cancelled the dialog - no changes are propagated.")


if __name__ == "__main__":

    with open(os.path.abspath(os.path.dirname(__file__) + "/../setup-wizard.json")) as f:
        ia = Interaction.from_json(json.load(f))
        runner = InteractionRunner(ia, ResotoClient("https://localhost:8900", None))
        runner.run()
