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
from resoto_digitalocean_client.model.associated_kubernetes_resources import AssociatedKubernetesResources
from resoto_digitalocean_client.model.cluster import Cluster
from resoto_digitalocean_client.model.cluster_registries import ClusterRegistries
from resoto_digitalocean_client.model.cluster_update import ClusterUpdate
from resoto_digitalocean_client.model.clusterlint_request import ClusterlintRequest
from resoto_digitalocean_client.model.clusterlint_results import ClusterlintResults
from resoto_digitalocean_client.model.credentials import Credentials
from resoto_digitalocean_client.model.destroy_associated_kubernetes_resources import DestroyAssociatedKubernetesResources
from resoto_digitalocean_client.model.error import Error
from resoto_digitalocean_client.model.inline_response2005 import InlineResponse2005
from resoto_digitalocean_client.model.kubernetes_node_pool import KubernetesNodePool
from resoto_digitalocean_client.model.kubernetes_node_pool_update import KubernetesNodePoolUpdate
from resoto_digitalocean_client.model.kubernetes_options import KubernetesOptions
from resoto_digitalocean_client.model.meta import Meta
from resoto_digitalocean_client.model.pagination import Pagination
from resoto_digitalocean_client.model.unknownbasetype import UNKNOWNBASETYPE,UNKNOWN_BASE_TYPE
from resoto_digitalocean_client.model.user import User


class KubernetesApi(object):
    """NOTE: This class is auto generated by OpenAPI Generator
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client
        self.add_kubernetes_node_pool_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools',
                'operation_id': 'add_kubernetes_node_pool',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'kubernetes_node_pool',
                ],
                'required': [
                    'cluster_id',
                    'kubernetes_node_pool',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'kubernetes_node_pool':
                        (KubernetesNodePool,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'kubernetes_node_pool': 'body',
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
        self.add_registry_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/registry',
                'operation_id': 'add_registry',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_registries',
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
                    'cluster_registries':
                        (ClusterRegistries,),
                },
                'attribute_map': {
                },
                'location_map': {
                    'cluster_registries': 'body',
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
        self.create_kubernetes_cluster_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters',
                'operation_id': 'create_kubernetes_cluster',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster',
                ],
                'required': [
                    'cluster',
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
                    'cluster':
                        (Cluster,),
                },
                'attribute_map': {
                },
                'location_map': {
                    'cluster': 'body',
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
        self.delete_kubernetes_cluster_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}',
                'operation_id': 'delete_kubernetes_cluster',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.delete_kubernetes_node_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools/{node_pool_id}/nodes/{node_id}',
                'operation_id': 'delete_kubernetes_node',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'node_pool_id',
                    'node_id',
                    'skip_drain',
                    'replace',
                ],
                'required': [
                    'cluster_id',
                    'node_pool_id',
                    'node_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'node_pool_id',
                    'node_id',
                    'skip_drain',
                    'replace',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('node_pool_id',): {

                    },
                    ('node_id',): {

                    },
                    ('skip_drain',): {

                        'inclusive_maximum': 1,
                        'inclusive_minimum': 0,
                    },
                    ('replace',): {

                        'inclusive_maximum': 1,
                        'inclusive_minimum': 0,
                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'node_pool_id':
                        (str,),
                    'node_id':
                        (str,),
                    'skip_drain':
                        (int,),
                    'replace':
                        (int,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'node_pool_id': 'node_pool_id',
                    'node_id': 'node_id',
                    'skip_drain': 'skip_drain',
                    'replace': 'replace',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'node_pool_id': 'path',
                    'node_id': 'path',
                    'skip_drain': 'query',
                    'replace': 'query',
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
        self.delete_kubernetes_node_pool_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools/{node_pool_id}',
                'operation_id': 'delete_kubernetes_node_pool',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'node_pool_id',
                ],
                'required': [
                    'cluster_id',
                    'node_pool_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'node_pool_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('node_pool_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'node_pool_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'node_pool_id': 'node_pool_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'node_pool_id': 'path',
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
        self.destroy_kubernetes_associated_resources_dangerous_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/destroy_with_associated_resources/dangerous',
                'operation_id': 'destroy_kubernetes_associated_resources_dangerous',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.destroy_kubernetes_associated_resources_selective_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/destroy_with_associated_resources/selective',
                'operation_id': 'destroy_kubernetes_associated_resources_selective',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'destroy_associated_kubernetes_resources',
                ],
                'required': [
                    'cluster_id',
                    'destroy_associated_kubernetes_resources',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'destroy_associated_kubernetes_resources':
                        (DestroyAssociatedKubernetesResources,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'destroy_associated_kubernetes_resources': 'body',
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
        self.get_available_upgrades_endpoint = _Endpoint(
            settings={
                'response_type': (InlineResponse2005,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/upgrades',
                'operation_id': 'get_available_upgrades',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.get_cluster_user_endpoint = _Endpoint(
            settings={
                'response_type': (User,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/user',
                'operation_id': 'get_cluster_user',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.get_clusterlint_results_endpoint = _Endpoint(
            settings={
                'response_type': (ClusterlintResults,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/clusterlint',
                'operation_id': 'get_clusterlint_results',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'run_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'run_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'run_id': 'run_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'run_id': 'query',
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
        self.get_credentials_endpoint = _Endpoint(
            settings={
                'response_type': (Credentials,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/credentials',
                'operation_id': 'get_credentials',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'expiry_seconds',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'expiry_seconds',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('expiry_seconds',): {

                        'inclusive_minimum': 0,
                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'expiry_seconds':
                        (int,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'expiry_seconds': 'expiry_seconds',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'expiry_seconds': 'query',
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
        self.get_kubeconfig_endpoint = _Endpoint(
            settings={
                'response_type': (str,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/kubeconfig',
                'operation_id': 'get_kubeconfig',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'expiry_seconds',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'expiry_seconds',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('expiry_seconds',): {

                        'inclusive_minimum': 0,
                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'expiry_seconds':
                        (int,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'expiry_seconds': 'expiry_seconds',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'expiry_seconds': 'query',
                },
                'collection_format_map': {
                }
            },
            headers_map={
                'accept': [
                    'application/yaml',
                    'application/json'
                ],
                'content_type': [],
            },
            api_client=api_client
        )
        self.get_kubernetes_cluster_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}',
                'operation_id': 'get_kubernetes_cluster',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.get_node_pool_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools/{node_pool_id}',
                'operation_id': 'get_node_pool',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'node_pool_id',
                ],
                'required': [
                    'cluster_id',
                    'node_pool_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'node_pool_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('node_pool_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'node_pool_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'node_pool_id': 'node_pool_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'node_pool_id': 'path',
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
        self.list_all_kubernetes_clusters_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters',
                'operation_id': 'list_all_kubernetes_clusters',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'per_page',
                    'page',
                ],
                'required': [],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'per_page',
                    'page',
                ]
            },
            root_map={
                'validations': {
                    ('per_page',): {

                        'inclusive_maximum': 200,
                        'inclusive_minimum': 1,
                    },
                    ('page',): {

                        'inclusive_minimum': 1,
                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'per_page':
                        (int,),
                    'page':
                        (int,),
                },
                'attribute_map': {
                    'per_page': 'per_page',
                    'page': 'page',
                },
                'location_map': {
                    'per_page': 'query',
                    'page': 'query',
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
        self.list_kubernetes_associated_resources_endpoint = _Endpoint(
            settings={
                'response_type': (AssociatedKubernetesResources,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/destroy_with_associated_resources',
                'operation_id': 'list_kubernetes_associated_resources',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.list_kubernetes_options_endpoint = _Endpoint(
            settings={
                'response_type': (KubernetesOptions,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/options',
                'operation_id': 'list_kubernetes_options',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
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
                },
                'attribute_map': {
                },
                'location_map': {
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
        self.list_node_pools_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools',
                'operation_id': 'list_node_pools',
                'http_method': 'GET',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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
        self.recycle_kubernetes_node_pool_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools/{node_pool_id}/recycle',
                'operation_id': 'recycle_kubernetes_node_pool',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'node_pool_id',
                    'unknown_base_type',
                ],
                'required': [
                    'cluster_id',
                    'node_pool_id',
                    'unknown_base_type',
                ],
                'nullable': [
                    'unknown_base_type',
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'node_pool_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('node_pool_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'node_pool_id':
                        (str,),
                    'unknown_base_type':
                        (UNKNOWN_BASE_TYPE,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'node_pool_id': 'node_pool_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'node_pool_id': 'path',
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
        self.remove_registry_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/registry',
                'operation_id': 'remove_registry',
                'http_method': 'DELETE',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_registries',
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
                    'cluster_registries':
                        (ClusterRegistries,),
                },
                'attribute_map': {
                },
                'location_map': {
                    'cluster_registries': 'body',
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
        self.run_clusterlint_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/clusterlint',
                'operation_id': 'run_clusterlint',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'clusterlint_request',
                ],
                'required': [
                    'cluster_id',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'clusterlint_request':
                        (ClusterlintRequest,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'clusterlint_request': 'body',
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
        self.update_kubernetes_cluster_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}',
                'operation_id': 'update_kubernetes_cluster',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'cluster_update',
                ],
                'required': [
                    'cluster_id',
                    'cluster_update',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'cluster_update':
                        (ClusterUpdate,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'cluster_update': 'body',
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
        self.update_kubernetes_node_pool_endpoint = _Endpoint(
            settings={
                'response_type': (bool, date, datetime, dict, float, int, list, str, none_type,),
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/node_pools/{node_pool_id}',
                'operation_id': 'update_kubernetes_node_pool',
                'http_method': 'PUT',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'node_pool_id',
                    'kubernetes_node_pool_update',
                ],
                'required': [
                    'cluster_id',
                    'node_pool_id',
                    'kubernetes_node_pool_update',
                ],
                'nullable': [
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                    'node_pool_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                    ('node_pool_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'node_pool_id':
                        (str,),
                    'kubernetes_node_pool_update':
                        (KubernetesNodePoolUpdate,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                    'node_pool_id': 'node_pool_id',
                },
                'location_map': {
                    'cluster_id': 'path',
                    'node_pool_id': 'path',
                    'kubernetes_node_pool_update': 'body',
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
        self.upgrade_kubernetes_cluster_endpoint = _Endpoint(
            settings={
                'response_type': None,
                'auth': [
                    'bearer_auth'
                ],
                'endpoint_path': '/v2/kubernetes/clusters/{cluster_id}/upgrade',
                'operation_id': 'upgrade_kubernetes_cluster',
                'http_method': 'POST',
                'servers': None,
            },
            params_map={
                'all': [
                    'cluster_id',
                    'unknown_base_type',
                ],
                'required': [
                    'cluster_id',
                    'unknown_base_type',
                ],
                'nullable': [
                    'unknown_base_type',
                ],
                'enum': [
                ],
                'validation': [
                    'cluster_id',
                ]
            },
            root_map={
                'validations': {
                    ('cluster_id',): {

                    },
                },
                'allowed_values': {
                },
                'openapi_types': {
                    'cluster_id':
                        (str,),
                    'unknown_base_type':
                        (UNKNOWN_BASE_TYPE,),
                },
                'attribute_map': {
                    'cluster_id': 'cluster_id',
                },
                'location_map': {
                    'cluster_id': 'path',
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

    def add_kubernetes_node_pool(
        self,
        cluster_id,
        kubernetes_node_pool,
        **kwargs
    ):
        """Add a Node Pool to a Kubernetes Cluster  # noqa: E501

        To add an additional node pool to a Kubernetes clusters, send a POST request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools` with the following attributes.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_kubernetes_node_pool(cluster_id, kubernetes_node_pool, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            kubernetes_node_pool (KubernetesNodePool):

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['kubernetes_node_pool'] = \
            kubernetes_node_pool
        return self.add_kubernetes_node_pool_endpoint.call_with_http_info(**kwargs)

    def add_registry(
        self,
        **kwargs
    ):
        """Add Container Registry to Kubernetes Clusters  # noqa: E501

        To integrate the container registry with Kubernetes clusters, send a POST request to `/v2/kubernetes/registry`.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.add_registry(async_req=True)
        >>> result = thread.get()


        Keyword Args:
            cluster_registries (ClusterRegistries): [optional]
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
        return self.add_registry_endpoint.call_with_http_info(**kwargs)

    def create_kubernetes_cluster(
        self,
        cluster,
        **kwargs
    ):
        """Create a New Kubernetes Cluster  # noqa: E501

        To create a new Kubernetes cluster, send a POST request to `/v2/kubernetes/clusters`. The request must contain at least one node pool with at least one worker.  The request may contain a maintenance window policy describing a time period when disruptive maintenance tasks may be carried out. Omitting the policy implies that a window will be chosen automatically. See [here](https://www.digitalocean.com/docs/kubernetes/how-to/upgrade-cluster/) for details.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.create_kubernetes_cluster(cluster, async_req=True)
        >>> result = thread.get()

        Args:
            cluster (Cluster):

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
        kwargs['cluster'] = \
            cluster
        return self.create_kubernetes_cluster_endpoint.call_with_http_info(**kwargs)

    def delete_kubernetes_cluster(
        self,
        cluster_id,
        **kwargs
    ):
        """Delete a Kubernetes Cluster  # noqa: E501

        To delete a Kubernetes cluster and all services deployed to it, send a DELETE request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID`.  A 204 status code with no body will be returned in response to a successful request.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_kubernetes_cluster(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
        kwargs['cluster_id'] = \
            cluster_id
        return self.delete_kubernetes_cluster_endpoint.call_with_http_info(**kwargs)

    def delete_kubernetes_node(
        self,
        cluster_id,
        node_pool_id,
        node_id,
        **kwargs
    ):
        """Delete a Node in a Kubernetes Cluster  # noqa: E501

        To delete a single node in a pool, send a DELETE request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools/$NODE_POOL_ID/nodes/$NODE_ID`.  Appending the `skip_drain=1` query parameter to the request causes node draining to be skipped. Omitting the query parameter or setting its value to `0` carries out draining prior to deletion.  Appending the `replace=1` query parameter to the request causes the node to be replaced by a new one after deletion. Omitting the query parameter or setting its value to `0` deletes without replacement.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_kubernetes_node(cluster_id, node_pool_id, node_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            node_pool_id (str): A unique ID that can be used to reference a Kubernetes node pool.
            node_id (str): A unique ID that can be used to reference a node in a Kubernetes node pool.

        Keyword Args:
            skip_drain (int): Specifies whether or not to drain workloads from a node before it is deleted. Setting it to `1` causes node draining to be skipped. Omitting the query parameter or setting its value to `0` carries out draining prior to deletion.. [optional] if omitted the server will use the default value of 0
            replace (int): Specifies whether or not to replace a node after it has been deleted. Setting it to `1` causes the node to be replaced by a new one after deletion. Omitting the query parameter or setting its value to `0` deletes without replacement.. [optional] if omitted the server will use the default value of 0
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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['node_pool_id'] = \
            node_pool_id
        kwargs['node_id'] = \
            node_id
        return self.delete_kubernetes_node_endpoint.call_with_http_info(**kwargs)

    def delete_kubernetes_node_pool(
        self,
        cluster_id,
        node_pool_id,
        **kwargs
    ):
        """Delete a Node Pool in a Kubernetes Cluster  # noqa: E501

        To delete a node pool, send a DELETE request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools/$NODE_POOL_ID`.  A 204 status code with no body will be returned in response to a successful request. Nodes in the pool will subsequently be drained and deleted.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.delete_kubernetes_node_pool(cluster_id, node_pool_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            node_pool_id (str): A unique ID that can be used to reference a Kubernetes node pool.

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['node_pool_id'] = \
            node_pool_id
        return self.delete_kubernetes_node_pool_endpoint.call_with_http_info(**kwargs)

    def destroy_kubernetes_associated_resources_dangerous(
        self,
        cluster_id,
        **kwargs
    ):
        """Delete a Cluster and All of its Associated Resources (Dangerous)  # noqa: E501

        To delete a Kubernetes cluster with all of its associated resources, send a DELETE request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/destroy_with_associated_resources/dangerous`. A 204 status code with no body will be returned in response to a successful request.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.destroy_kubernetes_associated_resources_dangerous(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
        kwargs['cluster_id'] = \
            cluster_id
        return self.destroy_kubernetes_associated_resources_dangerous_endpoint.call_with_http_info(**kwargs)

    def destroy_kubernetes_associated_resources_selective(
        self,
        cluster_id,
        destroy_associated_kubernetes_resources,
        **kwargs
    ):
        """Selectively Delete a Cluster and its Associated Resources  # noqa: E501

        To delete a Kubernetes cluster along with a subset of its associated resources, send a DELETE request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/destroy_with_associated_resources/selective`.  The JSON body of the request should include `load_balancers`, `volumes`, or `volume_snapshots` keys each set to an array of IDs for the associated resources to be destroyed.  The IDs can be found by querying the cluster's associated resources endpoint. Any associated resource not included in the request will remain and continue to accrue changes on your account.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.destroy_kubernetes_associated_resources_selective(cluster_id, destroy_associated_kubernetes_resources, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            destroy_associated_kubernetes_resources (DestroyAssociatedKubernetesResources):

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['destroy_associated_kubernetes_resources'] = \
            destroy_associated_kubernetes_resources
        return self.destroy_kubernetes_associated_resources_selective_endpoint.call_with_http_info(**kwargs)

    def get_available_upgrades(
        self,
        cluster_id,
        **kwargs
    ):
        """Retrieve Available Upgrades for an Existing Kubernetes Cluster  # noqa: E501

        To determine whether a cluster can be upgraded, and the versions to which it can be upgraded, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/upgrades`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_available_upgrades(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
            InlineResponse2005
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_available_upgrades_endpoint.call_with_http_info(**kwargs)

    def get_cluster_user(
        self,
        cluster_id,
        **kwargs
    ):
        """Retrieve User Information for a Kubernetes Cluster  # noqa: E501

        To show information the user associated with a Kubernetes cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/user`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_cluster_user(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
            User
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_cluster_user_endpoint.call_with_http_info(**kwargs)

    def get_clusterlint_results(
        self,
        cluster_id,
        **kwargs
    ):
        """Fetch Clusterlint Diagnostics for a Kubernetes Cluster  # noqa: E501

        To request clusterlint diagnostics for your cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/clusterlint`. If the `run_id` query parameter is provided, then the diagnostics for the specific run is fetched. By default, the latest results are shown.  To find out how to address clusterlint feedback, please refer to [the clusterlint check documentation](https://github.com/digitalocean/clusterlint/blob/master/checks.md).   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_clusterlint_results(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

        Keyword Args:
            run_id (str): Specifies the clusterlint run whose results will be retrieved.. [optional]
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
            ClusterlintResults
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_clusterlint_results_endpoint.call_with_http_info(**kwargs)

    def get_credentials(
        self,
        cluster_id,
        **kwargs
    ):
        """Retrieve Credentials for a Kubernetes Cluster  # noqa: E501

        This endpoint returns a JSON object . It can be used to programmatically construct Kubernetes clients which cannot parse kubeconfig files.  The resulting JSON object contains token-based authentication for clusters supporting it, and certificate-based authentication otherwise. For a list of supported versions and more information, see \"[How to Connect to a DigitalOcean Kubernetes Cluster with kubectl](https://www.digitalocean.com/docs/kubernetes/how-to/connect-with-kubectl/)\".  To retrieve credentials for accessing a Kubernetes cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/credentials`.  Clusters supporting token-based authentication may define an expiration by passing a duration in seconds as a query parameter to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/kubeconfig?expiry_seconds=$DURATION_IN_SECONDS`. If not set or 0, then the token will have a 7 day expiry. The query parameter has no impact in certificate-based authentication.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_credentials(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

        Keyword Args:
            expiry_seconds (int): The duration in seconds that the returned Kubernetes credentials will be valid. If not set or 0, the credentials will have a 7 day expiry.. [optional] if omitted the server will use the default value of 0
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
            Credentials
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_credentials_endpoint.call_with_http_info(**kwargs)

    def get_kubeconfig(
        self,
        cluster_id,
        **kwargs
    ):
        """Retrieve the kubeconfig for a Kubernetes Cluster  # noqa: E501

        This endpoint returns a kubeconfig file in YAML format. It can be used to connect to and administer the cluster using the Kubernetes command line tool, `kubectl`, or other programs supporting kubeconfig files (e.g., client libraries).  The resulting kubeconfig file uses token-based authentication for clusters supporting it, and certificate-based authentication otherwise. For a list of supported versions and more information, see \"[How to Connect to a DigitalOcean Kubernetes Cluster with kubectl](https://www.digitalocean.com/docs/kubernetes/how-to/connect-with-kubectl/)\".  To retrieve a kubeconfig file for use with a Kubernetes cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/kubeconfig`.  Clusters supporting token-based authentication may define an expiration by passing a duration in seconds as a query parameter to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/kubeconfig?expiry_seconds=$DURATION_IN_SECONDS`. If not set or 0, then the token will have a 7 day expiry. The query parameter has no impact in certificate-based authentication.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_kubeconfig(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

        Keyword Args:
            expiry_seconds (int): The duration in seconds that the returned Kubernetes credentials will be valid. If not set or 0, the credentials will have a 7 day expiry.. [optional] if omitted the server will use the default value of 0
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
            str
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_kubeconfig_endpoint.call_with_http_info(**kwargs)

    def get_kubernetes_cluster(
        self,
        cluster_id,
        **kwargs
    ):
        """Retrieve an Existing Kubernetes Cluster  # noqa: E501

        To show information about an existing Kubernetes cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_kubernetes_cluster(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
        kwargs['cluster_id'] = \
            cluster_id
        return self.get_kubernetes_cluster_endpoint.call_with_http_info(**kwargs)

    def get_node_pool(
        self,
        cluster_id,
        node_pool_id,
        **kwargs
    ):
        """Retrieve a Node Pool for a Kubernetes Cluster  # noqa: E501

        To show information about a specific node pool in a Kubernetes cluster, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools/$NODE_POOL_ID`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.get_node_pool(cluster_id, node_pool_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            node_pool_id (str): A unique ID that can be used to reference a Kubernetes node pool.

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['node_pool_id'] = \
            node_pool_id
        return self.get_node_pool_endpoint.call_with_http_info(**kwargs)

    def list_all_kubernetes_clusters(
        self,
        **kwargs
    ):
        """List All Kubernetes Clusters  # noqa: E501

        To list all of the Kubernetes clusters on your account, send a GET request to `/v2/kubernetes/clusters`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_all_kubernetes_clusters(async_req=True)
        >>> result = thread.get()


        Keyword Args:
            per_page (int): Number of items returned per page. [optional] if omitted the server will use the default value of 20
            page (int): Which 'page' of paginated results to return.. [optional] if omitted the server will use the default value of 1
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
        return self.list_all_kubernetes_clusters_endpoint.call_with_http_info(**kwargs)

    def list_kubernetes_associated_resources(
        self,
        cluster_id,
        **kwargs
    ):
        """List Associated Resources for Cluster Deletion  # noqa: E501

        To list the associated billable resources that can be destroyed along with a cluster, send a GET request to the `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/destroy_with_associated_resources` endpoint.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_kubernetes_associated_resources(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
            AssociatedKubernetesResources
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.list_kubernetes_associated_resources_endpoint.call_with_http_info(**kwargs)

    def list_kubernetes_options(
        self,
        **kwargs
    ):
        """List Available Regions, Node Sizes, and Versions of Kubernetes  # noqa: E501

        To list the versions of Kubernetes available for use, the regions that support Kubernetes, and the available node sizes, send a GET request to `/v2/kubernetes/options`.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_kubernetes_options(async_req=True)
        >>> result = thread.get()


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
            KubernetesOptions
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
        return self.list_kubernetes_options_endpoint.call_with_http_info(**kwargs)

    def list_node_pools(
        self,
        cluster_id,
        **kwargs
    ):
        """List All Node Pools in a Kubernetes Clusters  # noqa: E501

        To list all of the node pools in a Kubernetes clusters, send a GET request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.list_node_pools(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

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
        kwargs['cluster_id'] = \
            cluster_id
        return self.list_node_pools_endpoint.call_with_http_info(**kwargs)

    def recycle_kubernetes_node_pool(
        self,
        cluster_id,
        node_pool_id,
        unknown_base_type,
        **kwargs
    ):
        """Recycle a Kubernetes Node Pool  # noqa: E501

        The endpoint has been deprecated. Please use the DELETE `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools/$NODE_POOL_ID/nodes/$NODE_ID` method instead.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.recycle_kubernetes_node_pool(cluster_id, node_pool_id, unknown_base_type, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            node_pool_id (str): A unique ID that can be used to reference a Kubernetes node pool.
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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['node_pool_id'] = \
            node_pool_id
        kwargs['unknown_base_type'] = \
            unknown_base_type
        return self.recycle_kubernetes_node_pool_endpoint.call_with_http_info(**kwargs)

    def remove_registry(
        self,
        **kwargs
    ):
        """Remove Container Registry from Kubernetes Clusters  # noqa: E501

        To remove the container registry from Kubernetes clusters, send a DELETE request to `/v2/kubernetes/registry`.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.remove_registry(async_req=True)
        >>> result = thread.get()


        Keyword Args:
            cluster_registries (ClusterRegistries): [optional]
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
        return self.remove_registry_endpoint.call_with_http_info(**kwargs)

    def run_clusterlint(
        self,
        cluster_id,
        **kwargs
    ):
        """Run Clusterlint Checks on a Kubernetes Cluster  # noqa: E501

        Clusterlint helps operators conform to Kubernetes best practices around resources, security and reliability to avoid common problems while operating or upgrading the clusters.  To request a clusterlint run on your cluster, send a POST request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/clusterlint`. This will run all checks present in the `doks` group by default, if a request body is not specified. Optionally specify the below attributes.  For information about the available checks, please refer to [the clusterlint check documentation](https://github.com/digitalocean/clusterlint/blob/master/checks.md).   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.run_clusterlint(cluster_id, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.

        Keyword Args:
            clusterlint_request (ClusterlintRequest): [optional]
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
        kwargs['cluster_id'] = \
            cluster_id
        return self.run_clusterlint_endpoint.call_with_http_info(**kwargs)

    def update_kubernetes_cluster(
        self,
        cluster_id,
        cluster_update,
        **kwargs
    ):
        """Update a Kubernetes Cluster  # noqa: E501

        To update a Kubernetes cluster, send a PUT request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID` and specify one or more of the attributes below.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_kubernetes_cluster(cluster_id, cluster_update, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            cluster_update (ClusterUpdate):

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['cluster_update'] = \
            cluster_update
        return self.update_kubernetes_cluster_endpoint.call_with_http_info(**kwargs)

    def update_kubernetes_node_pool(
        self,
        cluster_id,
        node_pool_id,
        kubernetes_node_pool_update,
        **kwargs
    ):
        """Update a Node Pool in a Kubernetes Cluster  # noqa: E501

        To update the name of a node pool, edit the tags applied to it, or adjust its number of nodes, send a PUT request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/node_pools/$NODE_POOL_ID` with the following attributes.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.update_kubernetes_node_pool(cluster_id, node_pool_id, kubernetes_node_pool_update, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
            node_pool_id (str): A unique ID that can be used to reference a Kubernetes node pool.
            kubernetes_node_pool_update (KubernetesNodePoolUpdate):

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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['node_pool_id'] = \
            node_pool_id
        kwargs['kubernetes_node_pool_update'] = \
            kubernetes_node_pool_update
        return self.update_kubernetes_node_pool_endpoint.call_with_http_info(**kwargs)

    def upgrade_kubernetes_cluster(
        self,
        cluster_id,
        unknown_base_type,
        **kwargs
    ):
        """Upgrade a Kubernetes Cluster  # noqa: E501

        To immediately upgrade a Kubernetes cluster to a newer patch release of Kubernetes, send a POST request to `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/upgrade`. The body of the request must specify a version attribute.  Available upgrade versions for a cluster can be fetched from `/v2/kubernetes/clusters/$K8S_CLUSTER_ID/upgrades`.   # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True

        >>> thread = api.upgrade_kubernetes_cluster(cluster_id, unknown_base_type, async_req=True)
        >>> result = thread.get()

        Args:
            cluster_id (str): A unique ID that can be used to reference a Kubernetes cluster.
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
        kwargs['cluster_id'] = \
            cluster_id
        kwargs['unknown_base_type'] = \
            unknown_base_type
        return self.upgrade_kubernetes_cluster_endpoint.call_with_http_info(**kwargs)

