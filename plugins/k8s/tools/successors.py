import json

from resotoclient import ResotoClient


def get_successors(client: ResotoClient) -> None:
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
                print("successor_kinds: ClassVar[Dict[str, List[str]]] = " + json.dumps(succesors))


if __name__ == "__main__":
    get_successors(ResotoClient("https://localhost:8900", None))
