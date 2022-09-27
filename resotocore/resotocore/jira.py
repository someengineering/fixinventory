# This code sample uses the 'requests' library:
# http://docs.python-requests.org
import requests
from requests.auth import HTTPBasicAuth
import json

url = "https://some-engineering.atlassian.net/rest/api/2/issue"
# https://some-engineering.atlassian.net/jira/software/projects/SOM/boards/1

auth = HTTPBasicAuth("anja@some.engineering", "PycA9qfgTCmEgjM3DRtzA11A")

headers = {
   "Accept": "application/json",
   "Content-Type": "application/json"
}

payload = json.dumps( {
  "update": {
  },
  "fields": {
    "summary": "Resoto: Call to Cleanup",
    "parent": {
      "key": None
    },
    "issuetype": {
      "id": "10001"
    },
    "project": {
      "id": "10000"
    },
    "description": "Please look at these resources! \n Issue created by Resoto",
    "reporter": {
      "id": "6332bf1b234d44d406d208d1"
    },
    "labels": [
      "resoto",
      "cost-hazard"
    ],
    # "assignee": {
    #   "id": "5c8add8b-75d8-46a4-80ed-67cd01bda1b0"
    # }
  }
} )

response = requests.request(
   "POST",
   url,
   data=payload,
   headers=headers,
   auth=auth
)

print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))

# Add Attachment
# url = "https://your-domain.atlassian.net/rest/api/2/issue/{issueIdOrKey}/attachments"

#  auth = HTTPBasicAuth("email@example.com", "")

#  headers = {
#     "Accept": "application/json",
#     "X-Atlassian-Token": "no-check"
#  }

#  response = requests.request(
#     "POST",
#     url,
#     headers = headers,
#     auth = auth,
#     files = {
#          "file": ("myfile.txt", open("myfile.txt","rb"), "application-type")
#     }
#  )
