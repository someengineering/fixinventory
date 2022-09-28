# This code sample uses the 'requests' library:
# http://docs.python-requests.org
import requests
from requests.auth import HTTPBasicAuth
import json

url = "https://some-engineering.atlassian.net/rest/api/2/issue"
# https://some-engineering.atlassian.net/jira/software/projects/SOM/boards/1

auth = HTTPBasicAuth("anja@some.engineering", "PycA9qfgTCmEgjM3DRtzA11A") # needs to be a parameter/config

headers = {
   "Accept": "application/json",
   "Content-Type": "application/json"
}

payload = json.dumps( {
  "update": {
  },
  "fields": {
    "summary": "Resoto: Call to Action", # title?
    "parent": {
      "key": None
    },
    "issuetype": {
      "id": "10001"
    },
    "project": {
      "id": "10000" # needs to be a parameter/config
    },
    "description": "Please look at these resources! \n Issue created by Resoto", # message?
    "reporter": {
      "id": "6332bf1b234d44d406d208d1" # needs to be a parameter/config
    },
    "labels": [
      "resoto"
    ],
    "assignee": {
      "id": None # needs to be a parameter/config
    }
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

# Add Attachment, Optional Feature for the future?
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
