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
        """Login to Scarf and store the token and cookie in self.session."""
        if self.logged_in:
            return

        # We are only setting minimum required data here on purpose.
        #
        # If we wanted to make this indistinguishable from a browser we could replicate variations of:
        # EMAIL=my@email.com
        # PASSWORD=my_password
        # curl -H "Host: api.scarf.sh" -H "Cookie: scarf_context={%22_tag%22:%22None%22}" \
        #   -H "sec-ch-ua: \"Google Chrome\";v=\"105\", \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"105\"" \
        #   -H "accept: application/json" -H "content-type: application/json" -H "sec-ch-ua-mobile: ?0" \
        #   -H "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
        #   Chrome/105.0.0.0 Safari/537.36" -H "sec-ch-ua-platform: \"macOS\"" -H "origin: https://app.scarf.sh" \
        #   -H "sec-fetch-site: same-site" -H "sec-fetch-mode: cors" -H "sec-fetch-dest: empty" \
        #   -H "referer: https://app.scarf.sh/" -H "accept-language: en-US,en;q=0.9" \
        #   --data-binary "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" --compressed \
        #   "https://api.scarf.sh/internal/login"
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
        """Returns a ScarfOrganization object for the given organization name."""
        uri = f"{self.public_api}/organizations/{org}"
        r = self._get(uri)
        return ScarfOrganization.new(r)

    def packages(self) -> List[ScarfPackage]:
        """Returns a list of all packages for the logged in user."""
        uri = f"{self.public_api}/packages"
        r = self._get(uri)
        ps = []
        today = datetime.date.today().strftime("%Y-%m-%d")
        for package in r:
            p = ScarfPackage.new(package)
            metrics = self.insights(p, "2020-01-01", today)
            pull_count = 0
            for metric in metrics:
                pull_count += metric.get("count", 0)
            p.pull_count = pull_count
            ps.append(p)
        return ps

    def insights(self, package: ScarfPackage, start_date: str, end_date: str) -> dict:
        """Returns image download metrics for a package.

        Uses an internal API which is undocumented and likely not stable.
        However this seemed to be the only way to get download metrics for a package.
        """
        uri = f"{self.internal_api}/insights/{package.owner}/{package.id}/installs"
        params = {"start_date": start_date, "end_date": end_date}
        return self._get(uri, params=params)

    def _get(self, uri: str, headers: Optional[dict] = None, params: Optional[dict] = None) -> Optional[dict]:
        """HTTP GET a Scarf URI and return the JSON response using the logged in session."""
        self.login()
        log.debug(f"Getting {uri}")

        auth_headers = {"Authorization": f"Bearer {self.token}"}
        if headers is None:
            headers = auth_headers
        else:
            headers.update(auth_headers)

        r = self.session.get(uri, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Error requesting insights: {uri} {r.text} ({r.status_code})")
        return r.json()
