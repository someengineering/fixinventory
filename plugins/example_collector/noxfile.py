import nox
from nox.sessions import Session
from urllib.request import pathname2url
import os, webbrowser

nox.options.sessions = ["lint", "test"]
src_location = "resoto_plugin_example_collector"
all_locations = [src_location] + ["test"]


@nox.session(python=["3.8"])
def test(session: Session) -> None:
    args = session.posargs
    session.run("poetry", "install", external=True)
    session.run("pytest", *args)


@nox.session(python=["3.8"])
def lint(session) -> None:
    args = session.posargs or all_locations
    session.run("poetry", "install", external=True)
    session.run("black", "--check", "--diff", "--target-version", "py39", *args)
    session.run("flake8", src_location)


@nox.session(python=["3.8"])
def coverage(session) -> None:
    args = session.posargs
    session.run("poetry", "install", external=True)
    session.run("coverage", "run", "--source", src_location, "-m", "pytest", *args)
    session.run("coverage", "report", "-m", *args)
    session.run("coverage", "html", *args)
    webbrowser.open("file://" + pathname2url(os.path.abspath('htmlcov/index.html')))


@nox.session(python=["3.8"])
def ci(session) -> None:
    args = session.posargs
    session.run("poetry", "install", external=True)
    session.run("black", "--check", "--diff", "--target-version", "py39", *args)
    session.run("flake8", src_location)
    session.run("coverage", "run", "--source", src_location, "-m", "pytest", *args)
    session.run("coverage", "xml", *args)
