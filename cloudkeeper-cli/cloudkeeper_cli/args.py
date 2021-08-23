import os
import ast
import argparse

ENV_ARGS_PREFIX = "CLOUDKEEPER_CLI_"


class Namespace(argparse.Namespace):
    def __getattr__(self, item):
        return None


class ArgumentParser(argparse.ArgumentParser):
    # Class variable containing the last return value of parse_args()
    # If parse_args() hasn't been called yet will return None for any
    # attribute.
    args = Namespace()

    def parse_known_args(self, args=None, namespace=None):
        for action in self._actions:
            env_name = None
            for option_string in action.option_strings:
                if option_string.startswith("--"):
                    env_name = (
                        ENV_ARGS_PREFIX + option_string[2:].replace("-", "_").upper()
                    )
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
                    if action.type is not None:
                        type_goal = action.type
                    else:
                        type_goal = type(action.default)
                    if type_goal not in (str, int, float, complex, bool):
                        type_goal = str

                    if type_goal != str:
                        if isinstance(new_default, list):
                            for i, v in enumerate(new_default):
                                new_default[i] = convert(v, type_goal)
                        else:
                            new_default = convert(new_default, type_goal)
                    action.default = new_default
        ret_args, ret_argv = super().parse_known_args(args=args, namespace=namespace)
        ArgumentParser.args = ret_args
        return ret_args, ret_argv


def get_arg_parser(add_help: bool = True) -> ArgumentParser:
    arg_parser = ArgumentParser(description="Cloudkeeper CLI", add_help=add_help)
    arg_parser.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )
    return arg_parser


def convert(value, type_goal):
    try:
        converted_value = type_goal(ast.literal_eval(value))
    except ValueError:
        pass
    else:
        value = converted_value
    return value
