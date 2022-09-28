from resotolib.logger import log
from .resources import ScarfPackage, ScarfOrganization
from typing import Optional, List
import requests
import datetime


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

    def organization(self, org: str) -> ScarfOrganization:
        uri = f"{self.public_api}/organizations/{org}"
        r = self._get(uri)
        return ScarfOrganization.new(r)

    def packages(self) -> List[ScarfPackage]:
        uri = f"{self.public_api}/packages"
        r = self._get(uri)
        ps = []
        today = datetime.date.today().strftime("%Y-%m-%d")
        for package in r:
            p = ScarfPackage.new(package)
            metrics = self.insights(p, "2020-01-01", today)
            total_pulls = 0
            for metric in metrics:
                total_pulls += metric.get("count", 0)
            p.total_pulls = total_pulls
            ps.append(p)
        return ps

    def insights(self, package: ScarfPackage, start_date: str, end_date: str) -> dict:
        self.login()
        uri = f"{self.internal_api}/insights/{package.owner}/{package.id}/installs"
        params = {"start_date": start_date, "end_date": end_date}
        return self._get(uri, params=params)

    def _get(self, uri: str, headers: Optional[dict] = None, params: Optional[dict] = None) -> Optional[dict]:
        self.login()
        log.debug(f"Getting {uri}")
        auth_headers = {"Authorization": f"Bearer {self.token}"}
        headers = auth_headers if headers is None else headers.update(auth_headers)

        r = self.session.get(uri, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Error requesting insights: {uri} {r.text} ({r.status_code})")
        return r.json()
