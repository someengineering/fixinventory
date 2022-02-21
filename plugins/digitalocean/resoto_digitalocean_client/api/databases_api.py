"""
    DigitalOcean API

    # Introduction  The DigitalOcean API allows you to manage Droplets and resources within the DigitalOcean cloud in a simple, programmatic way using conventional HTTP requests.  All of the functionality that you are familiar with in the DigitalOcean control panel is also available through the API, allowing you to script the complex actions that your situation requires.  The API documentation will start with a general overview about the design and technology that has been implemented, followed by reference information about specific endpoints.  ## Requests  Any tool that is fluent in HTTP can communicate with the API simply by requesting the correct URI. Requests should be made using the HTTPS protocol so that traffic is encrypted. The interface responds to different methods depending on the action required.  |Method|Usage| |--- |--- | |GET|For simple retrieval of information about your account, Droplets, or environment, you should use the GET method.  The information you request will be returned to you as a JSON object. The attributes defined by the JSON object can be used to form additional requests.  Any request using the GET method is read-only and will not affect any of the objects you are querying.| |DELETE|To destroy a resource and remove it from your account and environment, the DELETE method should be used.  This will remove the specified object if it is found.  If it is not found, the operation will return a response indicating that the object was not found. This idempotency means that you do not have to check for a resource's availability prior to issuing a delete command, the final state will be the same regardless of its existence.| |PUT|To update the information about a resource in your account, the PUT method is available. Like the DELETE Method, the PUT method is idempotent.  It sets the state of the target using the provided values, regardless of their current values. Requests using the PUT method do not need to check the current attributes of the object.| |PATCH|Some resources support partial modification. In these cases, the PATCH method is available. Unlike PUT which generally requires a complete representation of a resource, a PATCH request is is a set of instructions on how to modify a resource updating only specific attributes.| |POST|To create a new object, your request should specify the POST method. The POST request includes all of the attributes necessary to create a new object.  When you wish to create a new object, send a POST request to the target endpoint.| |HEAD|Finally, to retrieve metadata information, you should use the HEAD method to get the headers.  This returns only the header of what would be returned with an associated GET request. Response headers contain some useful information about your API access and the results that are available for your request. For instance, the headers contain your current rate-limit value and the amount of time available until the limit resets. It also contains metrics about the total number of objects found, pagination information, and the total content length.|   ## HTTP Statuses  Along with the HTTP methods that the API responds to, it will also return standard HTTP statuses, including error codes.  In the event of a problem, the status will contain the error code, while the body of the response will usually contain additional information about the problem that was encountered.  In general, if the status returned is in the 200 range, it indicates that the request was fulfilled successfully and that no error was encountered.  Return codes in the 400 range typically indicate that there was an issue with the request that was sent. Among other things, this could mean that you did not authenticate correctly, that you are requesting an action that you do not have authorization for, that the object you are requesting does not exist, or that your request is malformed.  If you receive a status in the 500 range, this generally indicates a server-side problem. This means that we are having an issue on our end and cannot fulfill your request currently.  400 and 500 level error responses will include a JSON object in their body, including the following attributes:  |Name|Type|Description| |--- |--- |--- | |id|string|A short identifier corresponding to the HTTP status code returned. For example, the ID for a response returning a 404 status code would be \"not_found.\"| |message|string|A message providing additional information about the error, including details to help resolve it when possible.| |request_id|string|Optionally, some endpoints may include a request ID that should be provided when reporting bugs or opening support tickets to help identify the issue.|  ### Example Error Response  ```     HTTP/1.1 403 Forbidden     {       \"id\":       \"forbidden\",       \"message\":  \"You do not have access for the attempted action.\"     } ```  ## Responses  When a request is successful, a response body will typically be sent back in the form of a JSON object. An exception to this is when a DELETE request is processed, which will result in a successful HTTP 204 status and an empty response body.  Inside of this JSON object, the resource root that was the target of the request will be set as the key. This will be the singular form of the word if the request operated on a single object, and the plural form of the word if a collection was processed.  For example, if you send a GET request to `/v2/droplets/$DROPLET_ID` you will get back an object with a key called \"`droplet`\". However, if you send the GET request to the general collection at `/v2/droplets`, you will get back an object with a key called \"`droplets`\".  The value of these keys will generally be a JSON object for a request on a single object and an array of objects for a request on a collection of objects.  ### Response for a Single Object  ```     {         \"droplet\": {             \"name\": \"example.com\"             . . .         }     } ```  ### Response for an Object Collection  ```     {         \"droplets\": [             {                 \"name\": \"example.com\"                 . . .             },             {                 \"name\": \"second.com\"                 . . .             }         ]     } ```  ## Meta  In addition to the main resource root, the response may also contain a `meta` object. This object contains information about the response itself.  The `meta` object contains a `total` key that is set to the total number of objects returned by the request. This has implications on the `links` object and pagination.  The `meta` object will only be displayed when it has a value. Currently, the `meta` object will have a value when a request is made on a collection (like `droplets` or `domains`).   ### Sample Meta Object  ```     {         . . .         \"meta\": {             \"total\": 43         }         . . .     } ```  ## Links & Pagination  The `links` object is returned as part of the response body when pagination is enabled. By default, 20 objects are returned per page. If the response contains 20 objects or fewer, no `links` object will be returned. If the response contains more than 20 objects, the first 20 will be returned along with the `links` object.  You can request a different pagination limit or force pagination by appending `?per_page=` to the request with the number of items you would like per page. For instance, to show only two results per page, you could add `?per_page=2` to the end of your query. The maximum number of results per page is 200.  The `links` object contains a `pages` object. The `pages` object, in turn, contains keys indicating the relationship of additional pages. The values of these are the URLs of the associated pages. The keys will be one of the following:  *   **first**: The URI of the first page of results. *   **prev**: The URI of the previous sequential page of results. *   **next**: The URI of the next sequential page of results. *   **last**: The URI of the last page of results.  The `pages` object will only include the links that make sense. So for the first page of results, no `first` or `prev` links will ever be set. This convention holds true in other situations where a link would not make sense.  ### Sample Links Object  ```     {         . . .         \"links\": {             \"pages\": {                 \"last\": \"https://api.digitalocean.com/v2/images?page=2\",                 \"next\": \"https://api.digitalocean.com/v2/images?page=2\"             }         }         . . .     } ```  ## Rate Limit  Requests through the API are rate limited per OAuth token. Current rate limits:  *   5,000 requests per hour *   250 requests per minute (5% of the hourly total)  Once you exceed either limit, you will be rate limited until the next cycle starts. Space out any requests that you would otherwise issue in bursts for the best results.  The rate limiting information is contained within the response headers of each request. The relevant headers are:  *   **RateLimit-Limit**: The number of requests that can be made per hour. *   **RateLimit-Remaining**: The number of requests that remain before you hit your request limit. See the information below for how the request limits expire. *   **RateLimit-Reset**: This represents the time when the oldest request will expire. The value is given in [Unix epoch time](http://en.wikipedia.org/wiki/Unix_time). See below for more information about how request limits expire.  As long as the `RateLimit-Remaining` count is above zero, you will be able to make additional requests.  The way that a request expires and is removed from the current limit count is important to understand. Rather than counting all of the requests for an hour and resetting the `RateLimit-Remaining` value at the end of the hour, each request instead has its own timer.  This means that each request contributes toward the `RateLimit-Remaining` count for one complete hour after the request is made. When that request's timer runs out, it is no longer counted towards the request limit.  This has implications on the meaning of the `RateLimit-Reset` header as well. Because the entire rate limit is not reset at one time, the value of this header is set to the time when the _oldest_ request will expire.  Keep this in mind if you see your `RateLimit-Reset` value change, but not move an entire hour into the future.  If the `RateLimit-Remaining` reaches zero, subsequent requests will receive a 429 error code until the request reset has been reached. You can see the format of the response in the examples.  **Note:** The following endpoints have special rate limit requirements that are independent of the limits defined above.  *   Only 12 `POST` requests to the `/v2/floating_ips` endpoint to create Floating IPs can be made per 60 seconds. *   Only 10 `GET` requests to the `/v2/account/keys` endpoint to list SSH keys can be made per 60 seconds.  ### Sample Rate Limit Headers  ```     . . .     RateLimit-Limit: 1200     RateLimit-Remaining: 1193     RateLimit-Reset: 1402425459     . . . ```  ### Sample Rate Exceeded Response  ```     429 Too Many Requests     {             id: \"too_many_requests\",             message: \"API Rate limit exceeded.\"     } ```  ## Curl Examples  Throughout this document, some example API requests will be given using the `curl` command. This will allow us to demonstrate the various endpoints in a simple, textual format.      These examples assume that you are using a Linux or macOS command line. To run these commands on a Windows machine, you can either use cmd.exe, PowerShell, or WSL:  * For cmd.exe, use the `set VAR=VALUE` [syntax](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/set_1) to define environment variables, call them with `%VAR%`, then replace all backslashes (`\\`) in the examples with carets (`^`).  * For PowerShell, use the `$Env:VAR = \"VALUE\"` [syntax](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.2) to define environment variables, call them with `$Env:VAR`, then replace `curl` with `curl.exe` and all backslashes (`\\`) in the examples with backticks (`` ` ``).  * WSL is a compatibility layer that allows you to emulate a Linux terminal on a Windows machine. Install WSL with our [community tutorial](https://www.digitalocean.com/community/tutorials/how-to-install-the-windows-subsystem-for-linux-2-on-microsoft-windows-10),  then follow this API documentation normally.  The names of account-specific references (like Droplet IDs, for instance) will be represented by variables. For instance, a Droplet ID may be represented by a variable called `$DROPLET_ID`. You can set the associated variables in your environment if you wish to use the examples without modification.  The first variable that you should set to get started is your OAuth authorization token. The next section will go over the details of this, but you can set an environmental variable for it now.  Generate a token by going to the [Apps & API](https://cloud.digitalocean.com/settings/applications) section of the DigitalOcean control panel. Use an existing token if you have saved one, or generate a new token with the \"Generate new token\" button. Copy the generated token and use it to set and export the TOKEN variable in your environment as the example shows.  You may also wish to set some other variables now or as you go along. For example, you may wish to set the `DROPLET_ID` variable to one of your Droplet IDs since this will be used frequently in the API.  If you are following along, make sure you use a Droplet ID that you control so that your commands will execute correctly.  If you need access to the headers of a response through `curl`, you can pass the `-i` flag to display the header information along with the body. If you are only interested in the header, you can instead pass the `-I` flag, which will exclude the response body entirely.   ### Set and Export your OAuth Token  ``` export DIGITALOCEAN_TOKEN=your_token_here ```  ### Set and Export a Variable  ``` export DROPLET_ID=1111111 ```  ## Parameters  There are two different ways to pass parameters in a request with the API.  When passing parameters to create or update an object, parameters should be passed as a JSON object containing the appropriate attribute names and values as key-value pairs. When you use this format, you should specify that you are sending a JSON object in the header. This is done by setting the `Content-Type` header to `application/json`. This ensures that your request is interpreted correctly.  When passing parameters to filter a response on GET requests, parameters can be passed using standard query attributes. In this case, the parameters would be embedded into the URI itself by appending a `?` to the end of the URI and then setting each attribute with an equal sign. Attributes can be separated with a `&`. Tools like `curl` can create the appropriate URI when given parameters and values; this can also be done using the `-F` flag and then passing the key and value as an argument. The argument should take the form of a quoted string with the attribute being set to a value with an equal sign.  ### Pass Parameters as a JSON Object  ```     curl -H \"Authorization: Bearer $DIGITALOCEAN_TOKEN\" \\         -H \"Content-Type: application/json\" \\         -d '{\"name\": \"example.com\", \"ip_address\": \"127.0.0.1\"}' \\         -X POST \"https://api.digitalocean.com/v2/domains\" ```  ### Pass Filter Parameters as a Query String  ```      curl -H \"Authorization: Bearer $DIGITALOCEAN_TOKEN\" \\          -X GET \\          \"https://api.digitalocean.com/v2/images?private=true\" ```  ## Cross Origin Resource Sharing  In order to make requests to the API from other domains, the API implements Cross Origin Resource Sharing (CORS) support.  CORS support is generally used to create AJAX requests outside of the domain that the request originated from. This is necessary to implement projects like control panels utilizing the API. This tells the browser that it can send requests to an outside domain.  The procedure that the browser initiates in order to perform these actions (other than GET requests) begins by sending a \"preflight\" request. This sets the `Origin` header and uses the `OPTIONS` method. The server will reply back with the methods it allows and some of the limits it imposes. The client then sends the actual request if it falls within the allowed constraints.  This process is usually done in the background by the browser, but you can use curl to emulate this process using the example provided. The headers that will be set to show the constraints are:  *   **Access-Control-Allow-Origin**: This is the domain that is sent by the client or browser as the origin of the request. It is set through an `Origin` header. *   **Access-Control-Allow-Methods**: This specifies the allowed options for requests from that domain. This will generally be all available methods. *   **Access-Control-Expose-Headers**: This will contain the headers that will be available to requests from the origin domain. *   **Access-Control-Max-Age**: This is the length of time that the access is considered valid. After this expires, a new preflight should be sent. *   **Access-Control-Allow-Credentials**: This will be set to `true`. It basically allows you to send your OAuth token for authentication.  You should not need to be concerned with the details of these headers, because the browser will typically do all of the work for you.   # noqa: E501

    The version of the OpenAPI document: 2.0
    Contact: api-engineering@digitalocean.com
    Generated by: https://openapi-generator.tech
"""


import re  # noqa: F401
import sys  # noqa: F401

from resoto_digitalocean_client.api_client import ApiClient, Endpoint as _Endpoint
from resoto_digitalocean_client.model_utils import (  # noqa: F401
    check_allowed_values,
    check_validations,
    date,
    datetime,
    file_type,
    none_type,
    validate_and_convert_types
)
from resoto_digitalocean_client.model.connection_pool import ConnectionPool
from resoto_digitalocean_client.model.connection_pools import ConnectionPools
from resoto_digitalocean_client.model.database import Database
from resoto_digitalocean_client.model.database_backup import DatabaseBackup
from resoto_digitalocean_client.model.database_cluster import DatabaseCluster
from resoto_digitalocean_client.model.database_cluster_resize import DatabaseClusterResize
from resoto_digitalocean_client.model.database_maintenance_window import DatabaseMaintenanceWindow
from resoto_digitalocean_client.model.database_replica import DatabaseReplica
from resoto_digitalocean_client.model.database_user import DatabaseUser
from resoto_digitalocean_client.model.error import Error
from resoto_digitalocean_client.model.eviction_policy import EvictionPolicy
from resoto_digitalocean_client.model.inline_object1 import InlineObject1
from resoto_digitalocean_client.model.inline_object2 import InlineObject2
from resoto_digitalocean_client.model.inline_object3 import InlineObject3
from resoto_digitalocean_client.model.inline_response2001 import InlineResponse2001
from resoto_digitalocean_client.model.inline_response2002 import InlineResponse2002
from resoto_digitalocean_client.model.inline_response2011 import InlineResponse2011
from resoto_digitalocean_client.model.inline_response2012 import InlineResponse2012
from resoto_digitalocean_client.model.inline_response2013 import InlineResponse2013
from resoto_digitalocean_client.model.inline_response2014 import InlineResponse2014
from resoto_digitalocean_client.model.inline_response2015 import InlineResponse2015
from resoto_digitalocean_client.model.online_migration import OnlineMigration
from resoto_digitalocean_client.model.source_database import SourceDatabase
from resoto_digitalocean_client.model.sql_mode import SqlMode
from resoto_digitalocean_client.model.unknownbasetype import UNKNOWNBASETYPE


class DatabasesApi(object):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client
        self.add_connection_pool_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2015,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/pools',
                'operation_id': 'add_connection_pool',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'connection_pool',
                ],
                'required': [
                    'database_cluster_uuid',
                    'connection_pool',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'connection_pool':
                        (ConnectionPool,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'connection_pool': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.add_database_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2014,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/dbs',
                'operation_id': 'add_database',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database':
                        (Database,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.add_user_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2013,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/users',
                'operation_id': 'add_user',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database_user',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database_user',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database_user':
                        (DatabaseUser,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database_user': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.create_database_cluster_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2011,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases',
                'operation_id': 'create_database_cluster',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'unknown_base_type',
                ],
                'required': [
                    'unknown_base_type',
                ],
                'nullable': [
                    'unknown_base_type',
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'unknown_base_type':
                        (UNKNOWN_BASE_TYPE,),
                },
                'attribute_map': {
                },
                'location_map': {
                    'unknown_base_type': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.create_replica_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2012,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/replicas',
                'operation_id': 'create_replica',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'unknown_base_type',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                    'unknown_base_type',
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'unknown_base_type':
                        (UNKNOWN_BASE_TYPE,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'unknown_base_type': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.delete_connection_pool_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/pools/{pool_name}',
                'operation_id': 'delete_connection_pool',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'pool_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'pool_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'pool_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'pool_name': 'pool_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'pool_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.delete_database_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/dbs/{database_name}',
                'operation_id': 'delete_database',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'database_name': 'database_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.delete_online_migration_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/online-migration/{migration_id}',
                'operation_id': 'delete_online_migration',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'migration_id',
                ],
                'required': [
                    'database_cluster_uuid',
                    'migration_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'migration_id':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'migration_id': 'migration_id',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'migration_id': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.delete_user_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/users/{username}',
                'operation_id': 'delete_user',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'username',
                ],
                'required': [
                    'database_cluster_uuid',
                    'username',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'username':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'username': 'username',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'username': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.destroy_cluster_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}',
                'operation_id': 'destroy_cluster',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.destroy_replica_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/replicas/{replica_name}',
                'operation_id': 'destroy_replica',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'replica_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'replica_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'replica_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'replica_name': 'replica_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'replica_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_ca_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2001,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/ca',
                'operation_id': 'get_ca',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_connection_pool_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2015,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/pools/{pool_name}',
                'operation_id': 'get_connection_pool',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'pool_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'pool_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'pool_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'pool_name': 'pool_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'pool_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_database_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2014,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/dbs/{database_name}',
                'operation_id': 'get_database',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'database_name': 'database_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_database_cluster_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2011,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}',
                'operation_id': 'get_database_cluster',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_eviction_policy_endpoint = _Endpoint(
            settings={
                'response_type': (EvictionPolicy,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/eviction_policy',
                'operation_id': 'get_eviction_policy',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_migration_status_endpoint = _Endpoint(
            settings={
                'response_type': (OnlineMigration,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/online-migration',
                'operation_id': 'get_migration_status',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_replica_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2012,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/replicas/{replica_name}',
                'operation_id': 'get_replica',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'replica_name',
                ],
                'required': [
                    'database_cluster_uuid',
                    'replica_name',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'replica_name':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'replica_name': 'replica_name',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'replica_name': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_sql_mode_endpoint = _Endpoint(
            settings={
                'response_type': (SqlMode,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/sql_mode',
                'operation_id': 'get_sql_mode',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_user_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2013,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/users/{username}',
                'operation_id': 'get_user',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'username',
                ],
                'required': [
                    'database_cluster_uuid',
                    'username',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'username':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'username': 'username',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'username': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_connection_pools_endpoint = _Endpoint(
            settings={
                'response_type': (ConnectionPools,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/pools',
                'operation_id': 'list_connection_pools',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_database_backups_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2002,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/backups',
                'operation_id': 'list_database_backups',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_database_clusters_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases',
                'operation_id': 'list_database_clusters',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'tag_name',
                ],
                'required': [],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'tag_name':
                        (str,),
                },
                'attribute_map': {
                    'tag_name': 'tag_name',
                },
                'location_map': {
                    'tag_name': 'query',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_database_firewalls_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/firewall',
                'operation_id': 'list_database_firewalls',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_databases_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/dbs',
                'operation_id': 'list_databases',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_replicas_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/replicas',
                'operation_id': 'list_replicas',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.list_users_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/users',
                'operation_id': 'list_users',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                ],
                'required': [
                    'database_cluster_uuid',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.reset_auth_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2013,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/users/{username}/reset_auth',
                'operation_id': 'reset_auth',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'username',
                    'inline_object3',
                ],
                'required': [
                    'database_cluster_uuid',
                    'username',
                    'inline_object3',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'username':
                        (str,),
                    'inline_object3':
                        (InlineObject3,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                    'username': 'username',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'username': 'path',
                    'inline_object3': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_database_cluster_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/migrate',
                'operation_id': 'update_database_cluster',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'inline_object1',
                ],
                'required': [
                    'database_cluster_uuid',
                    'inline_object1',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'inline_object1':
                        (InlineObject1,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'inline_object1': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_database_cluster_size_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/resize',
                'operation_id': 'update_database_cluster_size',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database_cluster_resize',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database_cluster_resize',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database_cluster_resize':
                        (DatabaseClusterResize,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database_cluster_resize': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_database_firewall_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/firewall',
                'operation_id': 'update_database_firewall',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'inline_object2',
                ],
                'required': [
                    'database_cluster_uuid',
                    'inline_object2',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'inline_object2':
                        (InlineObject2,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'inline_object2': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_eviction_policy_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/eviction_policy',
                'operation_id': 'update_eviction_policy',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'eviction_policy',
                ],
                'required': [
                    'database_cluster_uuid',
                    'eviction_policy',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'eviction_policy':
                        (EvictionPolicy,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'eviction_policy': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_maintenance_window_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/maintenance',
                'operation_id': 'update_maintenance_window',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'database_maintenance_window',
                ],
                'required': [
                    'database_cluster_uuid',
                    'database_maintenance_window',
                ],
                'nullable': [
                    'database_maintenance_window',
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'database_maintenance_window':
                        (DatabaseMaintenanceWindow,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'database_maintenance_window': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_online_migration_endpoint = _Endpoint(
            settings={
                'response_type': (OnlineMigration,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/online-migration',
                'operation_id': 'update_online_migration',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'source_database',
                ],
                'required': [
                    'database_cluster_uuid',
                    'source_database',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'source_database':
                        (SourceDatabase,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'source_database': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )
        self.update_sql_mode_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/databases/{database_cluster_uuid}/sql_mode',
                'operation_id': 'update_sql_mode',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'database_cluster_uuid',
                    'sql_mode',
                ],
                'required': [
                    'database_cluster_uuid',
                    'sql_mode',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                ]
            },
            root_map={
                'validations': {
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'database_cluster_uuid':
                        (str,),
                    'sql_mode':
                        (SqlMode,),
                },
                'attribute_map': {
                    'database_cluster_uuid': 'database_cluster_uuid',
                },
                'location_map': {
                    'database_cluster_uuid': 'path',
                    'sql_mode': 'body',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/json'
                ],
                'content_type': [
                    'application/json'
                ]
            },
            api_client=api_client
        )

    def add_connection_pool(
        self,
        database_cluster_uuid,
        connection_pool,
        **kwargs
    ):
        """Add a New Connection Pool (PostgreSQL)  # noqa: E501

        For PostgreSQL database clusters, connection pools can be used to allow a database to share its idle connections. The popular PostgreSQL connection pooling utility PgBouncer is used to provide this service. [See here for more information](https://www.digitalocean.com/docs/databases/postgresql/how-to/manage-connection-pools/) about how and why to use PgBouncer connection pooling including details about the available transaction modes.  To add a new connection pool to a PostgreSQL database cluster, send a POST request to `/v2/databases/$DATABASE_ID/pools` specifying a name for the pool, the user to connect with, the database to connect to, as well as its desired size and transaction mode.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_connection_pool(database_cluster_uuid, connection_pool, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            connection_pool (ConnectionPool):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2015
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['connection_pool'] = \
            connection_pool
        return self.add_connection_pool_endpoint.call_with_http_info(**kwargs)

    def add_database(
        self,
        database_cluster_uuid,
        database,
        **kwargs
    ):
        """Add a New Database  # noqa: E501

        To add a new database to an existing cluster, send a POST request to `/v2/databases/$DATABASE_ID/dbs`.  Note: Database management is not supported for Redis clusters.  The response will be a JSON object with a key called `db`. The value of this will be an object that contains the standard attributes associated with a database.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_database(database_cluster_uuid, database, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database (Database):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2014
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database'] = \
            database
        return self.add_database_endpoint.call_with_http_info(**kwargs)

    def add_user(
        self,
        database_cluster_uuid,
        database_user,
        **kwargs
    ):
        """Add a Database User  # noqa: E501

        To add a new database user, send a POST request to `/v2/databases/$DATABASE_ID/users` with the desired username.  Note: User management is not supported for Redis clusters.  When adding a user to a MySQL cluster, additional options can be configured in the `mysql_settings` object.  The response will be a JSON object with a key called `user`. The value of this will be an object that contains the standard attributes associated with a database user including its randomly generated password.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_user(database_cluster_uuid, database_user, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database_user (DatabaseUser):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2013
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database_user'] = \
            database_user
        return self.add_user_endpoint.call_with_http_info(**kwargs)

    def create_database_cluster(
        self,
        unknown_base_type,
        **kwargs
    ):
        """Create a New Database Cluster  # noqa: E501

        To create a database cluster, send a POST request to `/v2/databases`. The response will be a JSON object with a key called `database`. The value of this will be an object that contains the standard attributes associated with a database cluster. The initial value of the database cluster's `status` attribute will be `creating`. When the cluster is ready to receive traffic, this will transition to `online`. The embedded `connection` and `private_connection` objects will contain the information needed to access the database cluster. DigitalOcean managed PostgreSQL and MySQL database clusters take automated daily backups. To create a new database cluster based on a backup of an exising cluster, send a POST request to `/v2/databases`. In addition to the standard database cluster attributes, the JSON body must include a key named `backup_restore` with the name of the original database cluster and the timestamp of the backup to be restored. Creating a database  from a backup is the same as forking a database in the control panel. Note: Backups are not supported for Redis clusters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.create_database_cluster(unknown_base_type, async_req=True)
        >>> result = thread.get()

        Args:
            unknown_base_type (UNKNOWN_BASE_TYPE):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2011
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['unknown_base_type'] = \
            unknown_base_type
        return self.create_database_cluster_endpoint.call_with_http_info(**kwargs)

    def create_replica(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Create a Read-only Replica  # noqa: E501

        To create a read-only replica for a PostgreSQL or MySQL database cluster, send a POST request to `/v2/databases/$DATABASE_ID/replicas` specifying the name it should be given, the size of the node to be used, and the region where it will be located. **Note**: Read-only replicas are not supported for Redis clusters. The response will be a JSON object with a key called `replica`. The value of this will be an object that contains the standard attributes associated with a database replica. The initial value of the read-only replica's `status` attribute will be `forking`. When the replica is ready to receive traffic, this will transition to `active`.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.create_replica(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            unknown_base_type (UNKNOWN_BASE_TYPE): [optional]
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2012
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.create_replica_endpoint.call_with_http_info(**kwargs)

    def delete_connection_pool(
        self,
        database_cluster_uuid,
        pool_name,
        **kwargs
    ):
        """Delete a Connection Pool (PostgreSQL)  # noqa: E501

        To delete a specific connection pool for a PostgreSQL database cluster, send a DELETE request to `/v2/databases/$DATABASE_ID/pools/$POOL_NAME`.  A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_connection_pool(database_cluster_uuid, pool_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            pool_name (str): The name used to identify the connection pool.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['pool_name'] = \
            pool_name
        return self.delete_connection_pool_endpoint.call_with_http_info(**kwargs)

    def delete_database(
        self,
        database_cluster_uuid,
        database_name,
        **kwargs
    ):
        """Delete a Database  # noqa: E501

        To delete a specific database, send a DELETE request to `/v2/databases/$DATABASE_ID/dbs/$DB_NAME`.  A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.  Note: Database management is not supported for Redis clusters.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_database(database_cluster_uuid, database_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database_name (str): The name of the database.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database_name'] = \
            database_name
        return self.delete_database_endpoint.call_with_http_info(**kwargs)

    def delete_online_migration(
        self,
        database_cluster_uuid,
        migration_id,
        **kwargs
    ):
        """Stop an Online Migration  # noqa: E501

        To stop an online migration, send a DELETE request to `/v2/databases/$DATABASE_ID/online-migration/$MIGRATION_ID`.  A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_online_migration(database_cluster_uuid, migration_id, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            migration_id (str): A unique identifier assigned to the online migration.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['migration_id'] = \
            migration_id
        return self.delete_online_migration_endpoint.call_with_http_info(**kwargs)

    def delete_user(
        self,
        database_cluster_uuid,
        username,
        **kwargs
    ):
        """Remove a Database User  # noqa: E501

        To remove a specific database user, send a DELETE request to `/v2/databases/$DATABASE_ID/users/$USERNAME`.  A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.  Note: User management is not supported for Redis clusters.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_user(database_cluster_uuid, username, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            username (str): The name of the database user.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['username'] = \
            username
        return self.delete_user_endpoint.call_with_http_info(**kwargs)

    def destroy_cluster(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Destroy a Database Cluster  # noqa: E501

        To destroy a specific database, send a DELETE request to `/v2/databases/$DATABASE_ID`. A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.destroy_cluster(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.destroy_cluster_endpoint.call_with_http_info(**kwargs)

    def destroy_replica(
        self,
        database_cluster_uuid,
        replica_name,
        **kwargs
    ):
        """Destroy a Read-only Replica  # noqa: E501

        To destroy a specific read-only replica, send a DELETE request to `/v2/databases/$DATABASE_ID/replicas/$REPLICA_NAME`. **Note**: Read-only replicas are not supported for Redis clusters. A status of 204 will be given. This indicates that the request was processed successfully, but that no response body is needed.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.destroy_replica(database_cluster_uuid, replica_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            replica_name (str): The name of the database replica.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['replica_name'] = \
            replica_name
        return self.destroy_replica_endpoint.call_with_http_info(**kwargs)

    def get_ca(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Retrieve the Public Certificate  # noqa: E501

        To retrieve the public certificate used to secure the connection to the database cluster send a GET request to `/v2/databases/$DATABASE_ID/ca`.  The response will be a JSON object with a `ca` key. This will be set to an object containing the base64 encoding of the public key certificate.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_ca(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2001
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.get_ca_endpoint.call_with_http_info(**kwargs)

    def get_connection_pool(
        self,
        database_cluster_uuid,
        pool_name,
        **kwargs
    ):
        """Retrieve Existing Connection Pool (PostgreSQL)  # noqa: E501

        To show information about an existing connection pool for a PostgreSQL database cluster, send a GET request to `/v2/databases/$DATABASE_ID/pools/$POOL_NAME`. The response will be a JSON object with a `pool` key.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_connection_pool(database_cluster_uuid, pool_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            pool_name (str): The name used to identify the connection pool.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2015
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['pool_name'] = \
            pool_name
        return self.get_connection_pool_endpoint.call_with_http_info(**kwargs)

    def get_database(
        self,
        database_cluster_uuid,
        database_name,
        **kwargs
    ):
        """Retrieve an Existing Database  # noqa: E501

        To show information about an existing database cluster, send a GET request to `/v2/databases/$DATABASE_ID/dbs/$DB_NAME`.  Note: Database management is not supported for Redis clusters.  The response will be a JSON object with a `db` key. This will be set to an object containing the standard database attributes.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_database(database_cluster_uuid, database_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database_name (str): The name of the database.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2014
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database_name'] = \
            database_name
        return self.get_database_endpoint.call_with_http_info(**kwargs)

    def get_database_cluster(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Retrieve an Existing Database Cluster  # noqa: E501

        To show information about an existing database cluster, send a GET request to `/v2/databases/$DATABASE_ID`. The response will be a JSON object with a database key. This will be set to an object containing the standard database cluster attributes. The embedded connection and private_connection objects will contain the information needed to access the database cluster. The embedded maintenance_window object will contain information about any scheduled maintenance for the database cluster.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_database_cluster(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2011
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.get_database_cluster_endpoint.call_with_http_info(**kwargs)

    def get_eviction_policy(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Retrieve the Eviction Policy for a Redis Cluster  # noqa: E501

        To retrieve the configured eviction policy for an existing Redis cluster, send a GET request to `/v2/databases/$DATABASE_ID/eviction_policy`. The response will be a JSON object with an `eviction_policy` key. This will be set to a string representing the eviction policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_eviction_policy(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            EvictionPolicy
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.get_eviction_policy_endpoint.call_with_http_info(**kwargs)

    def get_migration_status(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Retrieve the Status of an Online Migration  # noqa: E501

        To retrieve the status of an online migration, send a GET request to `/v2/databases/$DATABASE_ID/online-migration`. If a migration has completed, a 200 OK status is returned with no response body.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_migration_status(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            OnlineMigration
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.get_migration_status_endpoint.call_with_http_info(**kwargs)

    def get_replica(
        self,
        database_cluster_uuid,
        replica_name,
        **kwargs
    ):
        """Retrieve an Existing Read-only Replica  # noqa: E501

        To show information about an existing database replica, send a GET request to `/v2/databases/$DATABASE_ID/replicas/$REPLICA_NAME`. **Note**: Read-only replicas are not supported for Redis clusters. The response will be a JSON object with a `replica key`. This will be set to an object containing the standard database replica attributes.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_replica(database_cluster_uuid, replica_name, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            replica_name (str): The name of the database replica.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2012
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['replica_name'] = \
            replica_name
        return self.get_replica_endpoint.call_with_http_info(**kwargs)

    def get_sql_mode(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """Retrieve the SQL Modes for a MySQL Cluster  # noqa: E501

        To retrieve the configured SQL modes for an existing MySQL cluster, send a GET request to `/v2/databases/$DATABASE_ID/sql_mode`. The response will be a JSON object with a `sql_mode` key. This will be set to a string representing the configured SQL modes.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_sql_mode(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            SqlMode
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.get_sql_mode_endpoint.call_with_http_info(**kwargs)

    def get_user(
        self,
        database_cluster_uuid,
        username,
        **kwargs
    ):
        """Retrieve an Existing Database User  # noqa: E501

        To show information about an existing database user, send a GET request to `/v2/databases/$DATABASE_ID/users/$USERNAME`.  Note: User management is not supported for Redis clusters.  The response will be a JSON object with a `user` key. This will be set to an object containing the standard database user attributes.  For MySQL clusters, additional options will be contained in the mysql_settings object.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_user(database_cluster_uuid, username, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            username (str): The name of the database user.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2013
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['username'] = \
            username
        return self.get_user_endpoint.call_with_http_info(**kwargs)

    def list_connection_pools(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List Connection Pools (PostgreSQL)  # noqa: E501

        To list all of the connection pools available to a PostgreSQL database cluster, send a GET request to `/v2/databases/$DATABASE_ID/pools`. The result will be a JSON object with a `pools` key. This will be set to an array of connection pool objects.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_connection_pools(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            ConnectionPools
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_connection_pools_endpoint.call_with_http_info(**kwargs)

    def list_database_backups(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List Backups for a Database Cluster  # noqa: E501

        To list all of the available backups of a PostgreSQL or MySQL database cluster, send a GET request to `/v2/databases/$DATABASE_ID/backups`. **Note**: Backups are not supported for Redis clusters. The result will be a JSON object with a `backups key`. This will be set to an array of backup objects, each of which will contain the size of the backup and the timestamp at which it was created.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_database_backups(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2002
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_database_backups_endpoint.call_with_http_info(**kwargs)

    def list_database_clusters(
        self,
        **kwargs
    ):
        """List All Database Clusters  # noqa: E501

        To list all of the database clusters available on your account, send a GET request to `/v2/databases`. To limit the results to database clusters with a specific tag, include the `tag_name` query parameter set to the name of the tag. For example, `/v2/databases?tag_name=$TAG_NAME`. The result will be a JSON object with a `databases` key. This will be set to an array of database objects, each of which will contain the standard database attributes. The embedded `connection` and `private_connection` objects will contain the information needed to access the database cluster: The embedded `maintenance_window` object will contain information about any scheduled maintenance for the database cluster.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_database_clusters(async_req=True)
        >>> result = thread.get()


        Keyword Args:
            tag_name (str): Limits the results to database clusters with a specific tag.. [optional]
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            bool, date, datetime, dict, float, int, list, str, none_type
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        return self.list_database_clusters_endpoint.call_with_http_info(**kwargs)

    def list_database_firewalls(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List Firewall Rules (Trusted Sources) for a Database Cluster  # noqa: E501

        To list all of a database cluster's firewall rules (known as \"trusted sources\" in the control panel), send a GET request to `/v2/databases/$DATABASE_ID/firewall`. The result will be a JSON object with a `rules` key.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_database_firewalls(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            bool, date, datetime, dict, float, int, list, str, none_type
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_database_firewalls_endpoint.call_with_http_info(**kwargs)

    def list_databases(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List All Databases  # noqa: E501

        To list all of the databases in a clusters, send a GET request to `/v2/databases/$DATABASE_ID/dbs`.  The result will be a JSON object with a `dbs` key. This will be set to an array of database objects, each of which will contain the standard database attributes.  Note: Database management is not supported for Redis clusters.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_databases(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            bool, date, datetime, dict, float, int, list, str, none_type
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_databases_endpoint.call_with_http_info(**kwargs)

    def list_replicas(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List All Read-only Replicas  # noqa: E501

        To list all of the read-only replicas associated with a database cluster, send a GET request to `/v2/databases/$DATABASE_ID/replicas`. **Note**: Read-only replicas are not supported for Redis clusters. The result will be a JSON object with a `replicas` key. This will be set to an array of database replica objects, each of which will contain the standard database replica attributes.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_replicas(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            bool, date, datetime, dict, float, int, list, str, none_type
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_replicas_endpoint.call_with_http_info(**kwargs)

    def list_users(
        self,
        database_cluster_uuid,
        **kwargs
    ):
        """List all Database Users  # noqa: E501

        To list all of the users for your database cluster, send a GET request to `/v2/databases/$DATABASE_ID/users`.  Note: User management is not supported for Redis clusters.  The result will be a JSON object with a `users` key. This will be set to an array of database user objects, each of which will contain the standard database user attributes.  For MySQL clusters, additional options will be contained in the mysql_settings object.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_users(database_cluster_uuid, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            bool, date, datetime, dict, float, int, list, str, none_type
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        return self.list_users_endpoint.call_with_http_info(**kwargs)

    def reset_auth(
        self,
        database_cluster_uuid,
        username,
        inline_object3,
        **kwargs
    ):
        """Reset a Database User's Password or Authentication Method  # noqa: E501

        To reset the password for a database user, send a POST request to `/v2/databases/$DATABASE_ID/users/$USERNAME/reset_auth`.   For `mysql` databases, the authentication method can be specifying by including a key in the JSON body called `mysql_settings` with the `auth_plugin` value specified.  The response will be a JSON object with a `user` key. This will be set to an object containing the standard database user attributes.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.reset_auth(database_cluster_uuid, username, inline_object3, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            username (str): The name of the database user.
            inline_object3 (InlineObject3):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            InlineResponse2013
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['username'] = \
            username
        kwargs['inline_object3'] = \
            inline_object3
        return self.reset_auth_endpoint.call_with_http_info(**kwargs)

    def update_database_cluster(
        self,
        database_cluster_uuid,
        inline_object1,
        **kwargs
    ):
        """Migrate a Database Cluster to a New Region  # noqa: E501

        To migrate a database cluster to a new region, send a `PUT` request to `/v2/databases/$DATABASE_ID/migrate`. The body of the request must specify a `region` attribute.  A successful request will receive a 202 Accepted status code with no body in response. Querying the database cluster will show that its `status` attribute will now be set to `migrating`. This will transition back to `online` when the migration has completed.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_database_cluster(database_cluster_uuid, inline_object1, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            inline_object1 (InlineObject1):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['inline_object1'] = \
            inline_object1
        return self.update_database_cluster_endpoint.call_with_http_info(**kwargs)

    def update_database_cluster_size(
        self,
        database_cluster_uuid,
        database_cluster_resize,
        **kwargs
    ):
        """Resize a Database Cluster  # noqa: E501

        To resize a database cluster, send a PUT request to `/v2/databases/$DATABASE_ID/resize`. The body of the request must specify both the size and num_nodes attributes. A successful request will receive a 202 Accepted status code with no body in response. Querying the database cluster will show that its status attribute will now be set to resizing. This will transition back to online when the resize operation has completed.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_database_cluster_size(database_cluster_uuid, database_cluster_resize, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database_cluster_resize (DatabaseClusterResize):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database_cluster_resize'] = \
            database_cluster_resize
        return self.update_database_cluster_size_endpoint.call_with_http_info(**kwargs)

    def update_database_firewall(
        self,
        database_cluster_uuid,
        inline_object2,
        **kwargs
    ):
        """Update Firewall Rules (Trusted Sources) for a Database  # noqa: E501

        To update a database cluster's firewall rules (known as \"trusted sources\" in the control panel), send a PUT request to `/v2/databases/$DATABASE_ID/firewall` specifying which resources should be able to open connections to the database. You may limit connections to specific Droplets, Kubernetes clusters, or IP addresses. When a tag is provided, any Droplet or Kubernetes node with that tag applied to it will have access. The firewall is limited to 100 rules (or trusted sources). When possible, we recommend [placing your databases into a VPC network](https://www.digitalocean.com/docs/networking/vpc/) to limit access to them instead of using a firewall. A successful  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_database_firewall(database_cluster_uuid, inline_object2, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            inline_object2 (InlineObject2):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['inline_object2'] = \
            inline_object2
        return self.update_database_firewall_endpoint.call_with_http_info(**kwargs)

    def update_eviction_policy(
        self,
        database_cluster_uuid,
        eviction_policy,
        **kwargs
    ):
        """Configure the Eviction Policy for a Redis Cluster  # noqa: E501

        To configure an eviction policy for an existing Redis cluster, send a PUT request to `/v2/databases/$DATABASE_ID/eviction_policy` specifying the desired policy.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_eviction_policy(database_cluster_uuid, eviction_policy, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            eviction_policy (EvictionPolicy):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['eviction_policy'] = \
            eviction_policy
        return self.update_eviction_policy_endpoint.call_with_http_info(**kwargs)

    def update_maintenance_window(
        self,
        database_cluster_uuid,
        database_maintenance_window,
        **kwargs
    ):
        """Configure a Database Cluster's Maintenance Window  # noqa: E501

        To configure the window when automatic maintenance should be performed for a database cluster, send a PUT request to `/v2/databases/$DATABASE_ID/maintenance`. A successful request will receive a 204 No Content status code with no body in response.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_maintenance_window(database_cluster_uuid, database_maintenance_window, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            database_maintenance_window (DatabaseMaintenanceWindow):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['database_maintenance_window'] = \
            database_maintenance_window
        return self.update_maintenance_window_endpoint.call_with_http_info(**kwargs)

    def update_online_migration(
        self,
        database_cluster_uuid,
        source_database,
        **kwargs
    ):
        """Start an Online Migration  # noqa: E501

        To start an online migration, send a PUT request to `/v2/databases/$DATABASE_ID/online-migration` endpoint. Migrating a cluster establishes a connection with an existing cluster and replicates its contents to the target cluster. Online migration is only available for MySQL, PostgreSQL, and Redis clusters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_online_migration(database_cluster_uuid, source_database, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            source_database (SourceDatabase):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            OnlineMigration
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['source_database'] = \
            source_database
        return self.update_online_migration_endpoint.call_with_http_info(**kwargs)

    def update_sql_mode(
        self,
        database_cluster_uuid,
        sql_mode,
        **kwargs
    ):
        """Update SQL Mode for a Cluster  # noqa: E501

        To configure the SQL modes for an existing MySQL cluster, send a PUT request to `/v2/databases/$DATABASE_ID/sql_mode` specifying the desired modes. See the official MySQL 8 documentation for a [full list of supported SQL modes](https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html#sql-mode-full). A successful request will receive a 204 No Content status code with no body in response.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_sql_mode(database_cluster_uuid, sql_mode, async_req=True)
        >>> result = thread.get()

        Args:
            database_cluster_uuid (str): A unique identifier for a database cluster.
            sql_mode (SqlMode):

        Keyword Args:
            _return_http_data_only (bool): response data without head status
                code and headers. Default is True.
            _preload_content (bool): if False, the urllib3.HTTPResponse object
                will be returned without reading/decoding response data.
                Default is True.
            _request_timeout (int/float/tuple): timeout setting for this request. If
                one number provided, it will be total request timeout. It can also
                be a pair (tuple) of (connection, read) timeouts.
                Default is None.
            _check_input_type (bool): specifies if type checking
                should be done one the data sent to the server.
                Default is True.
            _check_return_type (bool): specifies if type checking
                should be done one the data received from the server.
                Default is True.
            _spec_property_naming (bool): True if the variable names in the input data
                are serialized names, as specified in the OpenAPI document.
                False if the variable names in the input data
                are pythonic names, e.g. snake case (default)
            _content_type (str/None): force body content-type.
                Default is None and content-type will be predicted by allowed
                content-types and body.
            _host_index (int/None): specifies the index of the server
                that we want to use.
                Default is read from the configuration.
            async_req (bool): execute request asynchronously

        Returns:
            None
                If the method is called asynchronously, returns the request
                thread.
        """
        kwargs['async_req'] = kwargs.get(
            'async_req', False
        )
        kwargs['_return_http_data_only'] = kwargs.get(
            '_return_http_data_only', True
        )
        kwargs['_preload_content'] = kwargs.get(
            '_preload_content', True
        )
        kwargs['_request_timeout'] = kwargs.get(
            '_request_timeout', None
        )
        kwargs['_check_input_type'] = kwargs.get(
            '_check_input_type', True
        )
        kwargs['_check_return_type'] = kwargs.get(
            '_check_return_type', True
        )
        kwargs['_spec_property_naming'] = kwargs.get(
            '_spec_property_naming', False
        )
        kwargs['_content_type'] = kwargs.get(
            '_content_type')
        kwargs['_host_index'] = kwargs.get('_host_index')
        kwargs['database_cluster_uuid'] = \
            database_cluster_uuid
        kwargs['sql_mode'] = \
            sql_mode
        return self.update_sql_mode_endpoint.call_with_http_info(**kwargs)

