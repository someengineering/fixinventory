from resotoclient import ResotoClient
from sqlalchemy import Engine

from cloud2sql.sql import SqlModel, SqlUpdater


def collect_from_resoto(engine: Engine) -> None:
    with ResotoClient("https://localhost:8900", None) as client:
        model = SqlModel(client.model())
        meta = model.create_schema()
        # engine = create_engine("sqlite:///:memory:", echo=True)

        meta.create_all(engine)
        updater = SqlUpdater(model)

        with engine.connect() as conn:
            for nd in client.search_graph("id(root) -[0:]->"):
                stmt = updater.insert_node(nd)
                if stmt is not None:
                    conn.execute(stmt)
            conn.commit()
