from .resources import ScarfOrganization
import requests


class ScarfAPI:
    def __init__(self, email: str, password: str) -> None:
        self.email = email
        self.password = password
        self.session = requests.Session()
        self.internal_api = "https://api.scarf.sh/internal"
        self.public_api = "http://scarf.sh/api/v1"
        self.token = None
        self.username = None
        self.logged_in = False

    def login(self) -> None:
        if self.logged_in:
            return

        payload = {"email": self.email, "password": self.password}
        headers = {"Content-Type": "application/json"}
        r = self.session.post(f"{self.internal_api}/login", json=payload, headers=headers)

        if r.status_code != 200:
            raise RuntimeError(f"Error login in: {r.text}_{r.status_code}")

        response_json = r.json()
        self.token = response_json.get("token")
        self.username = response_json.get("username")
        self.logged_in = True

    def insights(self, organization: ScarfOrganization, start_date: str, end_date: str) -> dict:
        self.login()
        uri = f"{self.internal_api}/insights/{organization.name}/{organization.id}/installs"
        params = {"start_date": start_date, "end_date": end_date}
        r = self.session.get(uri, params=params)

        if r.status_code != 200:
            raise RuntimeError(f"Error requesting insights: {r.text}_{r.status_code}")

        return r.json()
