from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from enum import Enum, unique
from functools import reduce
from typing import Optional, List, Dict, Any, Tuple, Union, Callable

from attr import define, field
from cattrs import Converter, gen
from resotoclient import ResotoClient

from resotolib.types import Json, JsonElement
from resotoshell.dialogs import CancelledException, ConversationFinishedException
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

    def render(self, value: Union[str, List[str]]) -> List[ActionResult]:
        def single(v: str) -> JsonElement:
            replaced = self.value_template.replace("@value@", str(v) if not isinstance(value, str) else value)
            return json.loads(replaced)  # type: ignore

        if value is None:
            return []
        else:
            js = [single(v) for v in value] if isinstance(value, list) else single(value)
            return [ActionResult(self.path, self.action, js)]


@define
class OnlyIf(ABC):
    @abstractmethod
    def is_true(self, js: Json) -> bool:
        pass

    @staticmethod
    def from_json_hook(converter: Converter) -> Callable[[Json, Any], OnlyIf]:
        defined = gen.make_dict_structure_fn(OnlyIfDefined, converter)
        undefined = gen.make_dict_structure_fn(OnlyIfUndefined, converter)
        value = gen.make_dict_structure_fn(OnlyIfValue, converter)

        def from_json(js: Json, other: Any) -> OnlyIf:
            if js.get("kind") == "defined":
                return defined(js, other)
            elif js.get("kind") == "undefined":
                return undefined(js, other)
            elif js.get("kind") == "value":
                return value(js, other)
            else:
                raise AttributeError(f"Don't know how to handle this step: {js}")

        return from_json


@define
class OnlyIfDefined(OnlyIf):
    path: str

    def is_true(self, js: Json) -> bool:
        return value_in_path(js, self.path) is not None


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
class Conversation:
    json_document: Json
    steps: List[Tuple[InteractionStep, List[ActionResult]]] = field(factory=list)

    def apply(self, step: InteractionStep, actions: List[ActionResult]) -> List[ActionResult]:
        update = self.json_document.copy()
        for action in actions:
            update = action.render(update)
        self.json_document = update
        self.steps.append((step, actions))
        return actions

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

    @abstractmethod
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        return [ActionResult(sp.path, sp.action, sp.value) for sp in self.patches]

    def execute_step(self, conversation: Conversation) -> List[ActionResult]:
        if conversation.should_execute(self):
            actions = self.execute(conversation)
            result = conversation.apply(self, actions)
            if self.is_terminal:
                raise ConversationFinishedException()
            return result
        else:
            return []

    @staticmethod
    def from_json_hook(converter: Converter) -> Callable[[Json, Any], InteractionStep]:
        info = gen.make_dict_structure_fn(InteractionInfo, converter)
        input = gen.make_dict_structure_fn(InteractionInput, converter)
        sub = gen.make_dict_structure_fn(SubInteraction, converter)
        seq = gen.make_dict_structure_fn(InteractionSequence, converter)
        decision = gen.make_dict_structure_fn(InteractionDecision, converter)

        def from_json(js: Json, other: Any) -> InteractionStep:
            if js.get("kind") == "info":
                return info(js, other)
            elif js.get("kind") == "input":
                return input(js, other)
            elif js.get("kind") == "sub_interaction":
                return sub(js, other)
            elif js.get("kind") == "seq":
                return seq(js, other)
            elif js.get("kind") == "decision":
                return decision(js, other)
            else:
                raise AttributeError(f"Don't know how to handle this step: {js}")

        return from_json


@define(kw_only=True)
class InteractionInfo(InteractionStep):
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        result = super().execute(conversation)
        message_dialog(title=self.name, text=self.help).run()
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

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        result: Union[None, str, List[str]] = ""
        if self.value_options is None:  # show simple text input field
            existing = value_in_path(conversation.json_document, self.action.path)
            ex_str = ", ".join(existing) if isinstance(existing, list) else str(existing)
            result = input_dialog(title=self.name, text=self.help, field_text=ex_str, password=self.password).run()
        else:
            width = reduce(lambda a, b: a + b, [len(a) for a in self.value_options])

            if width < 50:
                result = button_dialog(
                    title=self.name, text=self.help, buttons=[(k, v) for k, v in self.value_options.items()]
                ).run()
            else:
                result = radiolist_dialog(
                    title=self.name, text=self.help, values=[(v, k) for k, v in self.value_options.items()]
                ).run()
        if result is None:
            raise CancelledException()
        if split := self.split_result_by:
            result = re.split("\\s*" + re.escape(split) + "\\s*", result)
        else:
            result = None if result == "" else result  # interpret empty string as None
        return base + self.action.render(result)  # type: ignore # it can not be None here


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
                    title=self.name, text=self.help, values=[(k, k) for k in self.step_options]
                ).run()
            else:
                step_names = [
                    radiolist_dialog(title=self.name, text=self.help, values=[(k, k) for k in self.step_options]).run()
                ]

            if step_names is None or any(s is None for s in step_names):
                raise CancelledException()
            try:
                return base + [
                    result
                    for step_name in step_names
                    for result in self.step_options[step_name].execute_step(conversation)
                ]
            except CancelledException:
                pass  # user cancelled the sub dialog, represent the decision


@define(kw_only=True)
class SubInteraction(InteractionStep):
    path: str
    steps: List[InteractionStepUnion]

    def iterate(self, conversation: Conversation) -> Json:
        js: Optional[Json] = None
        for step in self.steps:
            for result in step.execute_step(conversation):
                js = result.render(js)
        return js or {}

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        result_list = []
        flag = True
        while flag:
            try:
                result_list.append(self.iterate(conversation))
            except CancelledException:
                pass
            # ask the user if he wants to do another
            flag = yes_no_dialog(title=self.name, text=self.help).run()
        return base + [ActionResult(self.path, JsonAction.replace, result_list)]


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
        conversation = Conversation(original)

        while count < len(self.interaction.steps):
            step = self.interaction.steps[count]
            try:
                step.execute_step(conversation)
                count += 1
            except CancelledException:
                # user cancelled this step, go back, if not already at the beginning
                if count == 0:
                    raise
                count -= 1
            except ConversationFinishedException:
                # terminal step reached for the current communication path. move on.
                count += 1
        return conversation

    def run(self) -> None:
        orig = self.client.config(self.interaction.config)
        conversation = self.interact(orig)
        print("Final config is: ", json.dumps(conversation.json_document, indent=2))
        self.client.put_config(self.interaction.config, conversation.json_document)


if __name__ == "__main__":

    with open("/Users/matthias/Documents/Work/someeng/resoto/resotoshell/setup-wizard.json") as f:
        js = json.load(f)
        interaction = Interaction.from_json(js)
        runner = InteractionRunner(interaction, ResotoClient("https://localhost:8900", None))
        runner.run()
