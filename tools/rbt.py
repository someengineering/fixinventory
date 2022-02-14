import argparse
from dataclasses import replace
import subprocess
import re


def bump_version(args):
    """
    Bump the version number in all poetry project files.
    """
    additional_project_names = [ 'core', 'shared_dev', 'shared-dev']
    replacement_rules = list(zip(additional_project_names, additional_project_names)) + [('resoto(.*)', 'resoto\g<1>')]

    projects_folders = ["shared_dev", "resotolib", "resotocore", "resotoworker", "resotoshell", "resotometrics", "plugins"]
    find_poetry_tomls = ["find"] + projects_folders + ["-name", "pyproject.toml"]
    find_poetry_locks = ["find"] + projects_folders + ["-name", "poetry.lock"]
    poetry_tomls = subprocess.run(find_poetry_tomls, cwd='./..', check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    poetry_locks = subprocess.run(find_poetry_locks, cwd='./..', check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    total_updates = 0

    print("Updating resoto dependency entries:")

    for file in poetry_locks.splitlines():

        file_updates = 0

        f = open(f'../{file}', 'r')
        updated = f.read()
        for replace_from, replace_to in replacement_rules:
            updated, nr_updates = re.subn(f'^\[\[package]]\nname = \"{replace_from}\"\nversion \= \"{args.bump_from}\"', f'[[package]]\nname = \"{replace_to}\"\nversion = \"{args.bump_to}\"', updated, flags=re.MULTILINE)
            total_updates += nr_updates
            file_updates += nr_updates

        f.close()

        f = open(f'../{file}', 'w')
        f.write(updated)
        f.close()

        if file_updates > 0:
            print(f'{file}: {file_updates}')


    for file in poetry_tomls.splitlines():

        file_updates = 0

        f = open(f'../{file}', 'r')
        updated = f.read()
        for replace_from, replace_to in replacement_rules:
            updated, nr_updates = re.subn(f'^\[tool\.poetry]\nname = \"{replace_from}\"\nversion \= \"{args.bump_from}\"', f'[tool.poetry]\nname = \"{replace_to}\"\nversion = \"{args.bump_to}\"', updated, flags=re.MULTILINE)
            total_updates += nr_updates
            file_updates += nr_updates

        f.close()

        f = open(f'../{file}', 'w') 
        f.write(updated)
        f.close()

        if file_updates > 0:
            print(f'{file}: {file_updates}')


    print(f'Total: {total_updates} entries.')


parser = argparse.ArgumentParser(description='Resoto Build Tool')

subparsers = parser.add_subparsers()
subparsers.required = True

bump_parser = subparsers.add_parser('bump', help='Bump version of all resoto components.')
bump_parser.add_argument('bump_from', help='Version to bump from.', type=str)
bump_parser.add_argument('bump_to', help='New version.',  type=str)
bump_parser.set_defaults(func=bump_version)

args = parser.parse_args()
args.func(args)
