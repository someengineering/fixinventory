import nox
from nox.sessions import Session

nox.options.sessions = ["lint", "test"]
locations = "core", "tests"


@nox.session(python=["3.8"])
def test(session: Session) -> None:
    args = session.posargs or locations
    session.run("poetry", "install", external=True)
    session.run("pytest", *args)


@nox.session(python=["3.8"])
def lint(session) -> None:
    args = session.posargs or locations
    core = session.posargs or "core"
    session.run("poetry", "install", external=True)
    session.run("black", "--line-length", "120", "--check", "--diff", "--target-version", "py39", *args)
    session.run("flake8", core)
    session.run("pylint", core)
    session.run("mypy", "--install-types", "--non-interactive", "--python-version", "3.8", "--strict", *args)


@nox.session(python=["3.8"])
def coverage(session) -> None:
    args = session.posargs
    session.run("poetry", "install", external=True)
    session.run("coverage", "run", "--source", "core", "-m", "pytest", *args)
    session.run("coverage", "combine", *args)
    session.run("coverage", "xml", *args)
