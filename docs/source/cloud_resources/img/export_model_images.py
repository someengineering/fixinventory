import requests

core = "http://localhost:8900"

kinds = requests.get(f"{core}/model").json()["kinds"]


def bases_of(name: str):
    kind = kinds[name]
    bases = kind.get("bases", [])
    result = list(bases)
    for base in bases:
        if base != name:
            result.extend(bases_of(base))
    return result


def export_images(path: str):
    filter_out = ["aws", "gcp"]
    for name, kind in kinds.items():
        if "bases" in kind and [a for a in filter_out if name.startswith(f"{a}_")]:
            show = [name, *bases_of(name)]
            image = requests.get(f"{core}/model/uml", params={"show": ",".join(show)})
            with open(f"{path}/{name}.svg", "w+") as file:
                file.write(image.text)


def print_rst(cloud: str):
    for name in sorted(kinds):
        if name.startswith(cloud):
            print(name)
            print("-" * len(name) + "\n")
            print(f".. image:: img/{name}.svg\n")


export_images(".")
