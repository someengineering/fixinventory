# # This code sample uses the 'requests' library:
# # http://docs.python-requests.org
import requests
from requests.auth import HTTPBasicAuth
import json

# url = "https://some-engineering.atlassian.net/rest/api/2/issue/createmeta"

# auth = HTTPBasicAuth("anja@some.engineering", "PycA9qfgTCmEgjM3DRtzA11A")

# headers = {
#    "Accept": "application/json"
# }

# response = requests.request(
#    "GET",
#    url,
#    headers=headers,
#    auth=auth
# )

# print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))

# {
#     "expand": "projects",
#     "projects": [
#         {
#             "avatarUrls": {
#                 "16x16": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10423?size=xsmall",
#                 "24x24": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10423?size=small",
#                 "32x32": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10423?size=medium",
#                 "48x48": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/project/avatar/10423"
#             },
#             "id": "10000",
#             "issuetypes": [
#                 {
#                     "description": "Tasks track small, distinct pieces of work.",
#                     "iconUrl": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/issuetype/avatar/10318?size=medium",
#                     "id": "10001",
#                     "name": "Task",
#                     "scope": {
#                         "project": {
#                             "id": "10000"
#                         },
#                         "type": "PROJECT"
#                     },
#                     "self": "https://some-engineering.atlassian.net/rest/api/2/issuetype/10001",
#                     "subtask": false,
#                     "untranslatedName": "Task"
#                 },
#                 {
#                     "description": "Epics track collections of related bugs, stories, and tasks.",
#                     "iconUrl": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/issuetype/avatar/10307?size=medium",
#                     "id": "10002",
#                     "name": "Epic",
#                     "scope": {
#                         "project": {
#                             "id": "10000"
#                         },
#                         "type": "PROJECT"
#                     },
#                     "self": "https://some-engineering.atlassian.net/rest/api/2/issuetype/10002",
#                     "subtask": false,
#                     "untranslatedName": "Epic"
#                 },
#                 {
#                     "description": "Subtasks track small pieces of work that are part of a larger task.",
#                     "iconUrl": "https://some-engineering.atlassian.net/rest/api/2/universal_avatar/view/type/issuetype/avatar/10316?size=medium",
#                     "id": "10003",
#                     "name": "Subtask",
#                     "scope": {
#                         "project": {
#                             "id": "10000"
#                         },
#                         "type": "PROJECT"
#                     },
#                     "self": "https://some-engineering.atlassian.net/rest/api/2/issuetype/10003",
#                     "subtask": true,
#                     "untranslatedName": "Subtask"
#                 }
#             ],
#             "key": "SOM",
#             "name": "SomeNotifications",
#             "self": "https://some-engineering.atlassian.net/rest/api/2/project/10000"
#         }
#     ]
# }

# This code sample uses the 'requests' library:
# http://docs.python-requests.org
url = "https://some-engineering.atlassian.net/rest/api/2/user/bulk/migration"
auth = HTTPBasicAuth("anja@some.engineering", "PycA9qfgTCmEgjM3DRtzA11A")
headers = {
   "Accept": "application/json"
}

response = requests.request(
   "GET",
   url,
   headers=headers,
   auth=auth
)

print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))
