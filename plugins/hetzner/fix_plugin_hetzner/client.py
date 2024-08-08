from hcloud import Client


def get_client(api_token: str) -> Client:
    return Client(token=api_token)
