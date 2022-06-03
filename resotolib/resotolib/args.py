import argparse
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from typing import List, Dict, Any, Union, Callable

DEFAULT_ENV_ARGS_PREFIX = "RESOTO_"


class Namespace(argparse.Namespace):
    def __getattr__(self, item):
        return None


class _MachineHelpAction(argparse.Action):
    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super(_MachineHelpAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_machine_help()
        parser.exit()


class ArgumentParser(argparse.ArgumentParser):
    # Class variable containing the last return value of parse_args()
    # If parse_args() hasn't been called yet will return None for any
    # attribute.
    args = Namespace()

    def __init__(
        self,
        *args,
        env_args_prefix: str = DEFAULT_ENV_ARGS_PREFIX,
        add_machine_help: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.env_args_prefix = env_args_prefix
        self.add_machine_help = add_machine_help
        self.register("action", "machine_help", _MachineHelpAction)

        if self.add_machine_help:
            self.add_argument(
                "--machine-help",
                action="machine_help",
                help="print machine readable help",
            )

    def print_machine_help(self):
        for action in self._actions:
            if action.default == argparse.SUPPRESS:
                continue
            for option_string in action.option_strings:
                print(option_string)

    def parse_known_args(self, args=None, namespace=None):
        for action in self._actions:
            env_name = None
            for option_string in action.option_strings:
                if option_string.startswith("--"):
                    env_name = self.env_args_prefix + option_string[2:].replace("-", "_").upper()
                    break
            if env_name is not None and action.default != argparse.SUPPRESS:
                new_default = None
                if action.nargs not in (0, None):
                    new_default = os.environ.get(env_name)
                    if new_default is not None:
                        new_default = new_default.split(" ")
                    else:
                        new_default = []
                        for i in range(255):
                            new_ittr_default = os.environ.get(env_name + str(i))
                            if new_ittr_default is not None:
                                new_default.append(new_ittr_default)
                        if len(new_default) == 0:
                            new_default = None
                else:
                    new_default = os.environ.get(env_name)

                if new_default is not None:
                    if isinstance(action.type, type):
                        type_goal = action.type
                    elif callable(action.type):
                        type_goal = action.type
                    else:
                        type_goal = type(action.default)

                    if isinstance(new_default, list):
                        new_default = [convert(n, type_goal) for n in new_default]
                    else:
                        new_default = convert(new_default, type_goal)

                    action.default = new_default
        ret_args, ret_argv = super().parse_known_args(args=args, namespace=namespace)
        ArgumentParser.args = ret_args
        return ret_args, ret_argv


def get_arg_parser(
    add_help: bool = True,
    description: str = "resoto",
    env_args_prefix: str = DEFAULT_ENV_ARGS_PREFIX,
) -> ArgumentParser:
    arg_parser = ArgumentParser(description=description, add_help=add_help, env_args_prefix=env_args_prefix)
    return arg_parser


# removed from types in 3.0-3.9: introduced again in 3.10
NoneType = type(None)


def convert(value: Any, type_goal: Union[type, Callable]) -> Any:
    if type_goal is NoneType:
        return value
    elif isinstance(type_goal, type):
        try:
            if type_goal in (str, int, float, complex):
                return type_goal(value)
            elif type_goal is bool:
                return value.lower() in ("true", "1", "yes")
            else:
                # don't know how to handle this type
                return value
        except Exception:
            # can not convert value
            return value
    elif callable(type_goal):
        return type_goal(value)


def args_dispatcher(dispatch_to: List, use_which: bool = False, argv: List = sys.argv[1:]) -> Dict[str, List[str]]:
    dispatch_args = defaultdict(list)
    prog_args = defaultdict(list)

    for prog in dispatch_to:
        cmd = prog
        if use_which:
            cmd = shutil.which(prog)
        result = subprocess.run([cmd, "--machine-help"], capture_output=True)
        if result.returncode != 0:
            continue
        for arg in result.stdout.decode("utf8").splitlines():
            prog_args[arg].append(prog)

    args = defaultdict(list)
    for i, arg in enumerate(argv):
        if arg.startswith("-"):
            arg_index = i + 1
            if len(argv) > arg_index:
                while not argv[arg_index].startswith("-"):
                    argval = str(argv[arg_index]).replace("'", "\\'")
                    args[arg].append(f"'{argval}'")
                    arg_index += 1
                    if len(argv) <= arg_index:
                        break
            if arg not in args:
                args[arg] = []

    for main_arg, arg_list in args.items():
        if main_arg in prog_args:
            for prog in prog_args[main_arg]:
                dispatch_args[prog].append(main_arg)
                dispatch_args[prog].extend(arg_list)

    return dict(dispatch_args)
