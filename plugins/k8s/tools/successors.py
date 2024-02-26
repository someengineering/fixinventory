import json

from fixclient import FixClient


def get_successors(client: FixClient) -> None:
    for name, kind in client.model().kinds.items():
        if name.startswith("kubernetes") and kind.aggregate_root:
            succesors = {}
            for edge_type in ["default", "delete"]:
                succesors[edge_type] = list(
                    client.cli_execute(
                        f"search is({name}) -{edge_type}-> | aggregate kind: sum(1) | jq --no-rewrite .group.kind"
                    )
                )
            if any(a for a in succesors.values()):
                print(name)
                print("reference_kinds: ClassVar[ModelReference] = " + json.dumps({"successors": succesors}))


if __name__ == "__main__":
    get_successors(FixClient("https://localhost:8900"))
