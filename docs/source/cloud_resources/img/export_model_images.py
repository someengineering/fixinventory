import requests

core = "http://localhost:8900"
kinds = requests.get(f"{core}/model").json()["kinds"]


def export_images(path: str):
    filter_out = ["aws", "gcp"]
    for name, kind in kinds.items():
        if [a for a in filter_out if name.startswith(f"{a}_")]:
            image = requests.get(f"{core}/model/uml", params={"show": name})
            with open(f"{path}/{name}.svg", "w+") as file:
                file.write(image.text)


def print_rst(cloud: str):
    for name in sorted(kinds):
        if name.startswith(cloud):
            print(name)
            print("-" * len(name) + "\n")
            print(f".. image:: img/{name}.svg\n")


export_images(".")
