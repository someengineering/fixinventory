from __future__ import annotations

import csv
import subprocess
import sys
from collections import namedtuple, defaultdict
from typing import Dict, List

import re

Commit = namedtuple(
    "Commit",
    ["commit_hash", "author", "component", "group", "message", "pr", "timestamp"],
)

group_names = {
    "feat": "Features",
    "fix": "Fixes",
    "docs": "Documentation",
    "chore": "Chores",
}
rewrite_component = {"api-docs": "docs", "README": "docs"}
rewrite_group = {"bug": "fix"}


def git_commits(from_tag: str, to_tag: str):
    return subprocess.run(
        [
            "git",
            "--no-pager",
            "log",
            "--pretty=format:%h§%aN§%s§%at",
            f"{from_tag}..{to_tag}",
        ],
        capture_output=True,
        text=True,
    ).stdout.splitlines()


def group_by(f, iterable):
    v = defaultdict(list)
    for item in iterable:
        key = f(item)
        v[key].append(item)
    return v


def parse_commit(row: list[str]) -> Commit:
    commit_hash, author, msg, time = row
    brackets = re.findall("\\[([^]]+)]", msg)
    if len(brackets) == 2:
        component, group = brackets
    elif len(brackets) == 1:
        component, group = brackets[0], "feat"
    else:
        component, group = "resoto", "feat"
    msg_pr = re.fullmatch("(?:\\[[^]]+]\\s*){0,2}(.*)\\(#(\\d+)\\)", msg)
    message, pr = msg_pr.groups() if msg_pr else (msg, "")
    return Commit(
        commit_hash,
        author,
        rewrite_component.get(component, component),
        rewrite_group.get(group, group),
        message,
        pr,
        time,
    )


def show_log(from_tag: str, to_tag: str):
    grouped: Dict[str, List[Commit]] = group_by(
        lambda c: c.group,
        [parse_commit(row) for row in csv.reader(git_commits(from_tag, to_tag), delimiter="§")],
    )

    print("---\ntags: [release notes]\n---")

    print(f"\n# v{to_tag}")

    print("\n## What's Changed")
    # define sort order for groups: order of group names and then the rest
    group_weights = defaultdict(lambda: 100, {a: num for num, a in enumerate(group_names)})
    for group, commits in sorted(grouped.items(), key=lambda x: group_weights[x[0]]):
        print(f"\n### {group_names.get(group, group)}\n")
        for commit in commits:
            print(
                f"- [`{commit.commit_hash}`](https://github.com/someengineering/resoto/commit/{commit.commit_hash}) "
                f'<span class="badge badge--secondary">{commit.component}</span> {commit.message}'
                f"{f' ([#{commit.pr}](https://github.com/someengineering/resoto/pull/{commit.pr}))' if commit.pr else ''}"
            )

    print("\n<!--truncate-->")
    print("\n## Docker Images\n")
    for image in ["resotocore", "resotoworker", "resotoshell", "resotometrics"]:
        print(f"- `somecr.io/someengineering/{image}:{to_tag}`")


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <from_tag> <to_tag>")
else:
    show_log(sys.argv[1], sys.argv[2])
