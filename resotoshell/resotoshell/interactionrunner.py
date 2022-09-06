from __future__ import annotations
import json
import re
from abc import ABC, abstractmethod
from enum import Enum, unique
from functools import reduce
from typing import Optional, List, Dict, ClassVar, Any, Tuple, Union

import cattrs

import cattrs
import jsons
from attr import define, field, evolve

from resotoshell.dialogs import (
    input_dialog,
    checkboxlist_dialog,
    button_dialog,
    yes_no_dialog,
    radiolist_dialog,
    message_dialog,
)
from resotolib.types import Json, JsonElement
from resotoshell.dialogs import CancelledException, ConversationFinishedException

SimpleType = str | int | float | bool


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
    patch: Json

    def render(self, js: Json) -> Json:
        parts = self.path.split(".") if self.path else []
        if len(parts) == 0 or js is None:
            return self.patch
        elif len(parts) == 1:
            js[self.path] = self.patch
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
    # action: JsonAction = JsonAction.replace
    action: str


@define
class PatchValueAction:
    path: str
    value_template: str
    action: JsonAction = JsonAction.replace

    def render(self, value: Union[str, List[str]]) -> List[ActionResult]:
        def single(v: str) -> JsonElement:
            replaced = self.value_template.replace("@value@", str(v) if not isinstance(value, str) else value)
            return json.loads(replaced)

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
    def value_in_path(js: Json, path: str) -> Optional[SimpleType]:
        parts = path.split(".")
        for part in parts:
            if isinstance(js, dict):
                js = js.get(part)
            else:
                return None
        return js

    @staticmethod
    def from_json_hook():
        defined = cattrs.gen.make_dict_structure_fn(OnlyIfDefined, cattrs.global_converter)
        undefined = cattrs.gen.make_dict_structure_fn(OnlyIfUndefined, cattrs.global_converter)
        value = cattrs.gen.make_dict_structure_fn(OnlyIfValue, cattrs.global_converter)

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
        return self.value_in_path(js, self.path) is not None


@define
class OnlyIfValue(OnlyIf):
    path: str
    value: JsonElement

    def is_true(self, js: Json) -> bool:
        return self.value_in_path(js, self.path) == self.value


@define
class OnlyIfUndefined(OnlyIf):
    path: str

    def is_true(self, js: Json) -> bool:
        return self.value_in_path(js, self.path) is None


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


@define(kw_only=True, slots=False)
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
    def from_json_hook():
        info = cattrs.gen.make_dict_structure_fn(InteractionInfo, cattrs.global_converter)
        input = cattrs.gen.make_dict_structure_fn(InteractionInput, cattrs.global_converter)
        sub = cattrs.gen.make_dict_structure_fn(SubInteraction, cattrs.global_converter)
        seq = cattrs.gen.make_dict_structure_fn(InteractionSequence, cattrs.global_converter)
        decision = cattrs.gen.make_dict_structure_fn(InteractionDecision, cattrs.global_converter)

        def from_json(js: Json, other: Any) -> InteractionStep:
            print(other)
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


@define(kw_only=True, slots=False)
class InteractionInfo(InteractionStep):
    def execute(self, conversation: Conversation) -> List[ActionResult]:
        result = super().execute(conversation)
        message_dialog(title=self.name, text=self.help).run()
        return result


@define(kw_only=True, slots=False)
class InteractionInput(InteractionStep):
    action: PatchValueAction
    # options to display -> value to use
    value_options: Optional[Dict[str, str]] = None
    # if this value is set, the input is splitted by this character and the result becomes a list
    split_result_by: Optional[str] = None

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        result = ""
        if self.value_options is None:  # show simple text input field
            result = input_dialog(title=self.name, text=self.help).run()
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
        return base + self.action.render(result)


@define(kw_only=True, slots=False)
class InteractionDecision(InteractionStep):
    select_multiple: bool = False
    # value to display -> wizard step to use
    step_options: Dict[str, InteractionStep]

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


@define(kw_only=True, slots=False)
class SubInteraction(InteractionStep):
    path: str
    steps: List[InteractionStep]

    def iterate(self, conversation: Conversation) -> Json:
        js = None
        for step in self.steps:
            for result in step.execute_step(conversation):
                js = result.render(js)
        return js

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


@define(kw_only=True, slots=False)
class InteractionSequence(InteractionStep):
    steps: List[InteractionStep]

    def execute(self, conversation: Conversation) -> List[ActionResult]:
        base = super().execute(conversation)
        return base + [res for step in self.steps for res in step.execute_step(conversation)]


class InteractionRunner:
    def __init__(self, steps: List[InteractionStep]):
        self.steps = steps

    def interact(self, original: Json) -> Conversation:
        count = 0
        conversation = Conversation(original)

        while count < len(self.steps):
            step = self.steps[count]
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

    @staticmethod
    def from_json(jsr: List[Json]) -> "InteractionRunner":
        steps = [cattrs.structure(js, InteractionStep) for js in jsr]
        return InteractionRunner(steps)


if __name__ == "__main__":
    aws = InteractionSequence(
        name="AWS",
        help="Configure AWS Collector",
        patches=[PatchStatic(path="resotoworker.collector", value=["aws"], action=JsonAction.merge)],
        steps=[
            InteractionDecision(
                name="AWS: how to access your AWS account(s)?",
                help="AWS allows several access methods to connect to your account(s). Which one do you want to use?",
                select_multiple=False,
                step_options={
                    "Resoto is running on a machine with a configured InstanceProfile": InteractionInfo(
                        name="InstanceProfile",
                        help="Using an instance profile does not require any additional configuration. You are all set!",
                    ),
                    "AWS access environment variables are provided to Resoto": InteractionInfo(
                        name="Environment Variables",
                        help="Using environment variables does not require any additional configuration. You are all set!",
                    ),
                    "I have an AWS AccessKey and Secret Key": InteractionSequence(
                        name="Access+Secret Key",
                        help="Configure Access and Secret Key",
                        steps=[
                            InteractionInput(
                                name="AWS Access Key",
                                help="Enter the AWS Access Key",
                                action=PatchValueAction("aws.access_key_id", '"@value@"'),
                            ),
                            InteractionInput(
                                name="AWS Secret Key",
                                help="Enter the AWS Secret Key",
                                action=PatchValueAction("aws.secret_access_key", '"@value@"'),
                            ),
                        ],
                    ),
                    "I would like to use AWS Profiles": InteractionInput(
                        name="AWS Profile(s) to use",
                        help="Enter the name of your profiles (separated by comma)",
                        action=PatchValueAction("aws.profiles", '"@value@"'),
                        split_result_by=",",
                    ),
                    "The Option I would like to use is not listed here": InteractionInfo(
                        name="Sorry",
                        help="This setup wizard is able to handle the most common cases to connect to AWS.\n"
                        "It looks we did not cover your use case.\n"
                        "Since most options to connect to AWS are implemented,\n"
                        "you might be able tp configure the access yourself by adjusting the configuration.\n"
                        "Please visit\n"
                        "https://resoto.com/docs/getting-started/configure-cloud-provider-access/aws\n"
                        "to see the possible configuration options.\n",
                        is_terminal=True,
                    ),
                },
            ),
            InteractionInput(
                id="aws_role",
                name="AWS: use a specific role?",
                help="In case you have setup a role that Resoto should assume, enter the role name here.\n"
                "A role is not required, leave the field empty if you do not want to use a role.",
                action=PatchValueAction("aws.role", '"@value@"'),
            ),
            InteractionInput(
                name="AWS: scrape organizations?",
                help="Do you want to scrape your organizations with the given role?",
                action=PatchValueAction("aws.scrape_org", "@value@"),
                value_options={"yes": "true", "no": "false"},
                only_if=[OnlyIfDefined("aws.role")],
            ),
            InteractionInput(
                name="AWS: Which accounts to scrape with this role?",
                help="It is possible to scrape different accounts with the role you have specified.\n"
                "Since the organization should not be scraped, do you want to define the list of accounts to scrape?\n"
                "If yes, enter all account ids separated by comma",
                split_result_by=",",
                action=PatchValueAction("aws.accounts", '"@value@"'),
                only_if=[OnlyIfValue("aws.scrape_org", False)],
            ),
            InteractionInput(
                name="AWS: Do you want to exclude specific accounts?",
                help="When the organization is scraped, all accounts in this organization are scraped.\n"
                "This is usually the preferred behaviour.\n\n"
                "In case you want to exclude specific accounts from Resoto,\n"
                "you can define a comma separated list of account ids here.\n"
                "All defined accounts will be excluded.",
                split_result_by=",",
                action=PatchValueAction("aws.accounts", '"@value@"'),
                only_if=[OnlyIfValue("aws.scrape_org", True)],
            ),
        ],
    )
    gcp = InteractionSequence(
        name="GCP",
        help="Configure Google Cloud Collector",
        patches=[PatchStatic(path="resotoworker.collector", value=["gcp"], action=JsonAction.merge)],
        steps=[],
    )
    kubernetes = InteractionSequence(
        name="Kubernetes",
        help="Configure Kubernetes Collector",
        patches=[PatchStatic(path="resotoworker.collector", value=["k8s"], action=JsonAction.merge)],
        steps=[],
    )
    digital_ocean = InteractionSequence(
        name="Digital Ocean",
        help="Configure DigitalOcean Collector",
        patches=[PatchStatic(path="resotoworker.collector", value=["digitalocean"], action=JsonAction.merge)],
        steps=[],
    )
    main = InteractionDecision(
        name="Which clouds do you use?",
        help="Some really helpful description here.",
        select_multiple=True,
        step_options={"AWS": aws, "GCP": gcp, "Kubernetes": kubernetes, "Digital Ocean": digital_ocean},
    )
    # cvs = InteractionRunner(steps=[main]).interact({"resotoworker": {"collector": ["gcp"]}})
    # print(cvs.json_document)

    # js = jsons.dump(main)
    #
    # cattrs.register_structure_hook(InteractionStep, lambda a, x: a)  # fake
    cattrs.register_structure_hook(InteractionStep, InteractionStep.from_json_hook())
    cattrs.register_structure_hook(OnlyIf, OnlyIf.from_json_hook())
    cattrs.register_structure_hook(JsonElement, lambda a, x: a)

    with open("/Users/matthias/Documents/Work/someeng/resoto/resotoshell/setup-wizard.json") as f:
        js = json.load(f)
        res = cattrs.structure(js, InteractionStep)

        print(json.dumps(jsons.dump(res), indent=2))

        # cvs = InteractionRunner(steps=[res]).interact({"resotoworker": {"collector": ["gcp"]}})
        # print(cvs.json_document)

    # dd = converter.structure(js, InteractionDecision)
    # print(json.dumps(js, indent=2))
    # print(json.dumps(again, indent=2))
