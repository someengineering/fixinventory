from logging import getLogger, basicConfig

from cloud2sql.collect_plugins import collect_from_plugins
from sqlalchemy import create_engine

log = getLogger("cloud2sql")


def main() -> None:
    basicConfig(level="INFO", filename="cloud2sql.log", force=True)
    engine = create_engine("sqlite:////tmp/resoto.db")
    collect_from_plugins(engine)


if __name__ == "__main__":
    main()
