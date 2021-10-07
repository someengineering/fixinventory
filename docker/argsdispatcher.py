#!/usr/bin/env python
from cklib.args import args_dispatcher
from pprint import pprint


def main():
    cmd_args = args_dispatcher(
        ["cksh", "ckworker", "ckcore", "ckmetrics"], use_which=True
    )
    pprint(cmd_args)


if __name__ == "__main__":
    main()
