import nox
from nox.sessions import Session

import tempfile

nox.options.sessions = "lint", "test", "black"
locations = "resoto_plugin_cleanup_untagged", "test", "noxfile.py"


def install_with_constraints(session: Session, *args, **kwargs):
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


@nox.session(python=["3.8", "3.9"])
def test(session: Session):
    args = session.posargs
    session.run("poetry", "install", "--no-dev", external=True)
    install_with_constraints(session, "coverage[toml]", "pytest", "pytest-cov")
    session.run("pytest", *args)


@nox.session(python=["3.9"])
def lint(session):
    args = session.posargs or locations
    install_with_constraints(session, "flake8", "flake8-black", "pep8-naming")
    session.run("flake8", "--verbose", *args)


@nox.session(python=["3.9"])
def black(session):
    args = session.posargs or locations
    install_with_constraints(session, "black")
    session.run("black", "--check", "--diff", *args)
