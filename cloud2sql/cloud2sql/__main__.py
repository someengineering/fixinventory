from argparse import Namespace, ArgumentParser
from logging import getLogger, basicConfig

from cloud2sql.collect_plugins import collect_from_plugins
from sqlalchemy import create_engine, Engine

log = getLogger("cloud2sql")


def parse_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", help="Path to config file", required=True)
    parser.add_argument(
        "--db",
        help="The database url. See https://docs.sqlalchemy.org/en/20/core/engines.html.",
        required=True,
    )
    return parser.parse_args()


def collect(engine: Engine, args: Namespace) -> None:
    try:
        collect_from_plugins(engine, args)
    except Exception as e:
        log.error("Error during collection", e)
        print(f"Error syncing data to database: {e}")


def main() -> None:
    args = parse_args()
    basicConfig(level="DEBUG" if args.debug else "INFO", filename="cloud2sql.log", force=True)
    engine = create_engine(args.db)
    collect(engine, args)


if __name__ == "__main__":
    main()
