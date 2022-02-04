import nox
from nox.sessions import Session

import tempfile

nox.options.sessions = ["lint", "test",  "black", "mypy"]
locations = "core", "tests"


def install_with_constraints(session: Session, *args, **kwargs) -> None:
    """
    This wrapper allows nox to use the exact versions of transitive dependencies
    captured in the poetry.lock file.
    """
    with tempfile.NamedTemporaryFile() as requirements:
        session.run(
            "poetry",
            "export",
            "--dev",
            "--without-hashes",
            "--format=requirements.txt",
            f"--output={requirements.name}",
            external=True,
        )
        session.install(f"--constraint={requirements.name}", *args, **kwargs)


@nox.session(python=["3.9"])
def test(session: Session) -> None:
    args = session.posargs
    session.run("poetry", "install", "--no-dev", external=True)
    install_with_constraints(
        session, "coverage[toml]", "pytest", "pytest-cov", "pytest-runner", "pytest-asyncio", "deepdiff", "hypothesis"
    )
    session.run("pytest", *args)


@nox.session(python=["3.9"])
def lint(session) -> None:
    args = session.posargs
    install_with_constraints(session, "flake8", "flake8-black", "pep8-naming", "pylint")
    session.run("flake8", "--verbose", "core", *args)


@nox.session(python=["3.9"])
def black(session) -> None:
    args = session.posargs or locations
    install_with_constraints(session, "black")
    session.run("black", "--line-length", "120", "--check", "--diff", "--target-version", "py39", *args)


@nox.session(python=["3.8"])
def mypy(session) -> None:
    args = session.posargs or locations
    session.run("poetry", "install", external=True)
    install_with_constraints(session, "mypy")
    session.run("mypy", "--install-types", "--non-interactive", "--python-version", "3.8", "--strict", *args)
