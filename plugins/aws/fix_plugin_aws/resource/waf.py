from __future__ import annotations

import logging
from typing import ClassVar, Dict, Optional, List, Type, Any

from attrs import define, field
from boto3.exceptions import Boto3Error

from fix_plugin_aws.resource.base import AwsApiSpec, AwsResource, GraphBuilder, parse_json
from fix_plugin_aws.utils import ToDict
from fixlib.baseresources import ModelReference
from fixlib.json_bender import Bender, S, Bend, ForallBend, ParseJson, MapDict
from fixlib.types import Json

log = logging.getLogger("fix.plugins.aws")
service_name = "wafv2"


@define(eq=False, slots=False)
class AwsWafCustomHTTPHeader:
    kind: ClassVar[str] = "aws_waf_custom_http_header"
    mapping: ClassVar[Dict[str, Bender]] = {"name": S("Name"), "value": S("Value")}
    name: Optional[str] = field(default=None, metadata={"description": "The name of the custom header."})  # fmt: skip
    value: Optional[str] = field(default=None, metadata={"description": "The value of the custom header."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCustomResponse:
    kind: ClassVar[str] = "aws_waf_custom_response"
    mapping: ClassVar[Dict[str, Bender]] = {
        "response_code": S("ResponseCode"),
        "custom_response_body_key": S("CustomResponseBodyKey"),
        "response_headers": S("ResponseHeaders", default=[]) >> ForallBend(AwsWafCustomHTTPHeader.mapping),
    }
    response_code: Optional[int] = field(default=None, metadata={"description": "The HTTP status code to return to the client."})  # fmt: skip
    custom_response_body_key: Optional[str] = field(default=None, metadata={"description": "References the response body that you want WAF to return to the web request client."})  # fmt: skip
    response_headers: Optional[List[AwsWafCustomHTTPHeader]] = field(factory=list, metadata={"description": "The HTTP headers to use in the response."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafDefaultAction:
    kind: ClassVar[str] = "aws_waf_default_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "block": S("Block", "CustomResponse") >> Bend(AwsWafCustomResponse.mapping),
        "allow": S("Allow", "CustomRequestHandling", "InsertHeaders") >> ForallBend(AwsWafCustomHTTPHeader.mapping),
    }
    block: Optional[AwsWafCustomResponse] = field(default=None, metadata={"description": "Specifies that WAF should block requests by default."})  # fmt: skip
    allow: Optional[List[AwsWafCustomHTTPHeader]] = field(default=None, metadata={"description": "Specifies that WAF should allow requests by default."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafJsonMatchPattern:
    kind: ClassVar[str] = "aws_waf_json_match_pattern"
    mapping: ClassVar[Dict[str, Bender]] = {
        "all": S("All"),
        "included_paths": S("IncludedPaths", default=[]),
    }
    all: Optional[Json] = field(default=None, metadata={"description": "Match all of the elements. See also MatchScope in JsonBody."})  # fmt: skip
    included_paths: Optional[List[str]] = field(factory=list, metadata={"description": "Match only the specified include paths."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafJsonBody:
    kind: ClassVar[str] = "aws_waf_json_body"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_pattern": S("MatchPattern") >> Bend(AwsWafJsonMatchPattern.mapping),
        "match_scope": S("MatchScope"),
        "invalid_fallback_behavior": S("InvalidFallbackBehavior"),
        "oversize_handling": S("OversizeHandling"),
    }
    match_pattern: Optional[AwsWafJsonMatchPattern] = field(default=None, metadata={"description": "The patterns to look for in the JSON body."})  # fmt: skip
    match_scope: Optional[str] = field(default=None, metadata={"description": "The parts of the JSON to match against using the MatchPattern."})  # fmt: skip
    invalid_fallback_behavior: Optional[str] = field(default=None, metadata={"description": "What WAF should do if it fails to completely parse the JSON body."})  # fmt: skip
    oversize_handling: Optional[str] = field(default=None, metadata={"description": "What WAF should do if the body is larger than WAF can inspect."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafHeaderMatchPattern:
    kind: ClassVar[str] = "aws_waf_header_match_pattern"
    mapping: ClassVar[Dict[str, Bender]] = {
        "all": S("All"),
        "included_headers": S("IncludedHeaders", default=[]),
        "excluded_headers": S("ExcludedHeaders", default=[]),
    }
    all: Optional[Json] = field(default=None, metadata={"description": "Inspect all headers."})  # fmt: skip
    included_headers: Optional[List[str]] = field(factory=list, metadata={"description": "Inspect only the headers that have a key that matches one of the strings specified here."})  # fmt: skip
    excluded_headers: Optional[List[str]] = field(factory=list, metadata={"description": "Inspect only the headers whose keys don't match any of the strings specified here."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafHeaders:
    kind: ClassVar[str] = "aws_waf_headers"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_pattern": S("MatchPattern") >> Bend(AwsWafHeaderMatchPattern.mapping),
        "match_scope": S("MatchScope"),
        "oversize_handling": S("OversizeHandling"),
    }
    match_pattern: Optional[AwsWafHeaderMatchPattern] = field(default=None, metadata={"description": "The filter to use to identify the subset of headers to inspect in a web request."})  # fmt: skip
    match_scope: Optional[str] = field(default=None, metadata={"description": "The parts of the headers to match with the rule inspection criteria. If you specify ALL, WAF inspects both keys and values."})  # fmt: skip
    oversize_handling: Optional[str] = field(default=None, metadata={"description": "What WAF should do if the headers of the request are more numerous or larger than WAF can inspect."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCookieMatchPattern:
    kind: ClassVar[str] = "aws_waf_cookie_match_pattern"
    mapping: ClassVar[Dict[str, Bender]] = {
        "all": S("All"),
        "included_cookies": S("IncludedCookies", default=[]),
        "excluded_cookies": S("ExcludedCookies", default=[]),
    }
    all: Optional[Json] = field(default=None, metadata={"description": "Inspect all cookies."})  # fmt: skip
    included_cookies: Optional[List[str]] = field(factory=list, metadata={"description": "Inspect only the cookies that have a key that matches one of the strings specified here."})  # fmt: skip
    excluded_cookies: Optional[List[str]] = field(factory=list, metadata={"description": "Inspect only the cookies whose keys don't match any of the strings specified here."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCookies:
    kind: ClassVar[str] = "aws_waf_cookies"
    mapping: ClassVar[Dict[str, Bender]] = {
        "match_pattern": S("MatchPattern") >> Bend(AwsWafCookieMatchPattern.mapping),
        "match_scope": S("MatchScope"),
        "oversize_handling": S("OversizeHandling"),
    }
    match_pattern: Optional[AwsWafCookieMatchPattern] = field(default=None, metadata={"description": "The filter to use to identify the subset of cookies to inspect in a web request."})  # fmt: skip
    match_scope: Optional[str] = field(default=None, metadata={"description": "The parts of the cookies to inspect with the rule inspection criteria. If you specify ALL, WAF inspects both keys and values."})  # fmt: skip
    oversize_handling: Optional[str] = field(default=None, metadata={"description": "What WAF should do if the cookies of the request are more numerous or larger than WAF can inspect."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafFieldToMatch:
    kind: ClassVar[str] = "aws_waf_field_to_match"
    mapping: ClassVar[Dict[str, Bender]] = {
        "single_header": S("SingleHeader", "Name"),
        "single_query_argument": S("SingleQueryArgument", "Name"),
        "all_query_arguments": S("AllQueryArguments"),
        "uri_path": S("UriPath"),
        "query_string": S("QueryString"),
        "body": S("Body", "OversizeHandling"),
        "method": S("Method"),
        "json_body": S("JsonBody") >> Bend(AwsWafJsonBody.mapping),
        "headers": S("Headers") >> Bend(AwsWafHeaders.mapping),
        "cookies": S("Cookies") >> Bend(AwsWafCookies.mapping),
        "header_order": S("HeaderOrder", "OversizeHandling"),
        "ja3_fingerprint": S("JA3Fingerprint", "FallbackBehavior"),
    }
    single_header: Optional[str] = field(default=None, metadata={"description": "Inspect a single header. Provide the name of the header to inspect, for example, User-Agent or Referer. This setting isn't case sensitive."})  # fmt: skip
    single_query_argument: Optional[str] = field(default=None, metadata={"description": "Inspect a single query argument. Provide the name of the query argument to inspect, such as UserName or SalesRegion. The name can "})  # fmt: skip
    all_query_arguments: Optional[Json] = field(default=None, metadata={"description": "Inspect all query arguments."})  # fmt: skip
    uri_path: Optional[Json] = field(default=None, metadata={"description": "Inspect the request URI path. This is the part of the web request that identifies a resource, for example, /images/daily-ad.jpg."})  # fmt: skip
    query_string: Optional[Json] = field(default=None, metadata={"description": "Inspect the query string. This is the part of a URL that appears after a ? character, if any."})  # fmt: skip
    body: Optional[str] = field(default=None, metadata={"description": "Inspect the request body as plain text. The request body immediately follows the request headers."})  # fmt: skip
    method: Optional[Json] = field(default=None, metadata={"description": "Inspect the HTTP method. The method indicates the type of operation that the request is asking the origin to perform."})  # fmt: skip
    json_body: Optional[AwsWafJsonBody] = field(default=None, metadata={"description": "Inspect the request body as JSON. The request body immediately follows the request headers."})  # fmt: skip
    headers: Optional[AwsWafHeaders] = field(default=None, metadata={"description": "Inspect the request headers."})  # fmt: skip
    cookies: Optional[AwsWafCookies] = field(default=None, metadata={"description": "Inspect the request cookies."})  # fmt: skip
    header_order: Optional[str] = field(default=None, metadata={"description": "Inspect a string containing the list of the request's header names, ordered as they appear in the web request that WAF receives for inspection"})  # fmt: skip
    ja3_fingerprint: Optional[str] = field(default=None, metadata={"description": "Match against the request's JA3 fingerprint. The JA3 fingerprint is a 32-character hash derived from the TLS Client Hello of an incoming request."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafTextTransformation:
    kind: ClassVar[str] = "aws_waf_text_transformation"
    mapping: ClassVar[Dict[str, Bender]] = {"priority": S("Priority"), "type": S("Type")}
    priority: Optional[int] = field(default=None, metadata={"description": "Sets the relative processing order for multiple transformations. WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content."})  # fmt: skip
    type: Optional[str] = field(default=None, metadata={"description": "For detailed descriptions of each of the transformation types, see Text transformations in the WAF Developer Guide."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafByteMatchStatement:
    kind: ClassVar[str] = "aws_waf_byte_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "search_string": S("SearchString"),
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
        "positional_constraint": S("PositionalConstraint"),
    }
    search_string: Optional[str] = field(default=None, metadata={"description": "A string value that you want WAF to search for. WAF searches only in the part of web requests that you designate for inspection in FieldToMatch."})  # fmt: skip
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip
    positional_constraint: Optional[str] = field(default=None, metadata={"description": "The area within the portion of the web request that you want WAF to search for SearchString."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafSqliMatchStatement:
    kind: ClassVar[str] = "aws_waf_sqli_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
        "sensitivity_level": S("SensitivityLevel"),
    }
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip
    sensitivity_level: Optional[str] = field(default=None, metadata={"description": "The sensitivity that you want WAF to use to inspect for SQL injection attacks."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafXssMatchStatement:
    kind: ClassVar[str] = "aws_waf_xss_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
    }
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafSizeConstraintStatement:
    kind: ClassVar[str] = "aws_waf_size_constraint_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "comparison_operator": S("ComparisonOperator"),
        "size": S("Size"),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
    }
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    comparison_operator: Optional[str] = field(default=None, metadata={"description": "The operator to use to compare the request part to the size setting."})  # fmt: skip
    size: Optional[int] = field(default=None, metadata={"description": "The size, in byte, to compare to the request part, after any transformations."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafForwardedIPConfig:
    kind: ClassVar[str] = "aws_waf_forwarded_ip_config"
    mapping: ClassVar[Dict[str, Bender]] = {"header_name": S("HeaderName"), "fallback_behavior": S("FallbackBehavior")}
    header_name: Optional[str] = field(default=None, metadata={"description": "The name of the HTTP header to use for the IP address. For example, to use the X-Forwarded-For (XFF) header, set this to X-Forwarded-For. "})  # fmt: skip
    fallback_behavior: Optional[str] = field(default=None, metadata={"description": "The match status to assign to the web request if the request doesn't have a valid IP address in the specified position."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafGeoMatchStatement:
    kind: ClassVar[str] = "aws_waf_geo_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "country_codes": S("CountryCodes", default=[]),
        "forwarded_ip_config": S("ForwardedIPConfig") >> Bend(AwsWafForwardedIPConfig.mapping),
    }
    country_codes: Optional[List[str]] = field(factory=list, metadata={"description": "An array of two-character country codes that you want to match against, for example, [ US, CN ], from the alpha-2 country ISO codes of the ISO 3166 international standard."})  # fmt: skip
    forwarded_ip_config: Optional[AwsWafForwardedIPConfig] = field(default=None, metadata={"description": "The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCountAction:
    kind: ClassVar[str] = "aws_waf_count_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_request_handling": S("CustomRequestHandling", "InsertHeaders")
        >> ForallBend(AwsWafCustomHTTPHeader.mapping)
    }
    custom_request_handling: Optional[List[AwsWafCustomHTTPHeader]] = field(default=None, metadata={"description": "Defines custom handling for the web request. For information about customizing web requests and responses, see Customizing web requests and responses in WAF in the WAF Developer Guide."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCaptchaAction:
    kind: ClassVar[str] = "aws_waf_captcha_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_request_handling": S("CustomRequestHandling", "InsertHeaders")
        >> ForallBend(AwsWafCustomHTTPHeader.mapping)
    }
    custom_request_handling: Optional[List[AwsWafCustomHTTPHeader]] = field(default=None, metadata={"description": "Defines custom handling for the web request, used when the CAPTCHA inspection determines that the request's token is valid and unexpired."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafChallengeAction:
    kind: ClassVar[str] = "aws_waf_challenge_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "custom_request_handling": S("CustomRequestHandling", "InsertHeaders")
        >> ForallBend(AwsWafCustomHTTPHeader.mapping)
    }
    custom_request_handling: Optional[List[AwsWafCustomHTTPHeader]] = field(default=None, metadata={"description": "Defines custom handling for the web request, used when the challenge inspection determines that the request's token is valid and unexpired."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRuleAction:
    kind: ClassVar[str] = "aws_waf_rule_action"
    mapping: ClassVar[Dict[str, Bender]] = {
        "block": S("Block", "CustomResponse") >> Bend(AwsWafCustomResponse.mapping),
        "allow": S("Allow", "CustomRequestHandling", "InsertHeaders") >> ForallBend(AwsWafCustomHTTPHeader.mapping),
        "count": S("Count") >> Bend(AwsWafCountAction.mapping),
        "captcha": S("Captcha") >> Bend(AwsWafCaptchaAction.mapping),
        "challenge": S("Challenge") >> Bend(AwsWafChallengeAction.mapping),
    }
    block: Optional[AwsWafCustomResponse] = field(default=None, metadata={"description": "Instructs WAF to block the web request."})  # fmt: skip
    allow: Optional[List[AwsWafCustomHTTPHeader]] = field(default=None, metadata={"description": "Instructs WAF to allow the web request."})  # fmt: skip
    count: Optional[AwsWafCountAction] = field(default=None, metadata={"description": "Instructs WAF to count the web request and then continue evaluating the request using the remaining rules in the web ACL."})  # fmt: skip
    captcha: Optional[AwsWafCaptchaAction] = field(default=None, metadata={"description": "Instructs WAF to run a CAPTCHA check against the web request."})  # fmt: skip
    challenge: Optional[AwsWafChallengeAction] = field(default=None, metadata={"description": "Instructs WAF to run a Challenge check against the web request."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRuleActionOverride:
    kind: ClassVar[str] = "aws_waf_rule_action_override"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "action_to_use": S("ActionToUse") >> Bend(AwsWafRuleAction.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the rule to override."})  # fmt: skip
    action_to_use: Optional[AwsWafRuleAction] = field(default=None, metadata={"description": "The override action to use, in place of the configured action of the rule in the rule group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRuleGroupReferenceStatement:
    kind: ClassVar[str] = "aws_waf_rule_group_reference_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("ARN"),
        "excluded_rules": S("ExcludedRules", default=[]) >> ForallBend(S("Name")),
        "rule_action_overrides": S("RuleActionOverrides", default=[]) >> ForallBend(AwsWafRuleActionOverride.mapping),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the entity."})  # fmt: skip
    excluded_rules: Optional[List[str]] = field(factory=list, metadata={"description": "Rules in the referenced rule group whose actions are set to Count.   Instead of this option, use RuleActionOverrides."})  # fmt: skip
    rule_action_overrides: Optional[List[AwsWafRuleActionOverride]] = field(factory=list, metadata={"description": "Action settings to use in the place of the rule actions that are configured inside the rule group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafIPSetForwardedIPConfig:
    kind: ClassVar[str] = "aws_waf_ip_set_forwarded_ip_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "header_name": S("HeaderName"),
        "fallback_behavior": S("FallbackBehavior"),
        "position": S("Position"),
    }
    header_name: Optional[str] = field(default=None, metadata={"description": "The name of the HTTP header to use for the IP address."})  # fmt: skip
    fallback_behavior: Optional[str] = field(default=None, metadata={"description": "The match status to assign to the web request if the request doesn't have a valid IP address in the specified position."})  # fmt: skip
    position: Optional[str] = field(default=None, metadata={"description": "The position in the header to search for the IP address. "})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafIPSetReferenceStatement:
    kind: ClassVar[str] = "aws_waf_ip_set_reference_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("ARN"),
        "ip_set_forwarded_ip_config": S("IPSetForwardedIPConfig") >> Bend(AwsWafIPSetForwardedIPConfig.mapping),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the IPSet that this statement references."})  # fmt: skip
    ip_set_forwarded_ip_config: Optional[AwsWafIPSetForwardedIPConfig] = field(default=None, metadata={"description": "The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRegexPatternSetReferenceStatement:
    kind: ClassVar[str] = "aws_waf_regex_pattern_set_reference_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "arn": S("ARN"),
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
    }
    arn: Optional[str] = field(default=None, metadata={"description": "The Amazon Resource Name (ARN) of the RegexPatternSet that this statement references."})  # fmt: skip
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRateLimit:
    kind: ClassVar[str] = "aws_waf_rate_limit"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the header to use."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRateLimitUriPath:
    kind: ClassVar[str] = "aws_waf_rate_limit_uri_path"
    mapping: ClassVar[Dict[str, Bender]] = {
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping)
    }
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRateBasedStatementCustomKey:
    kind: ClassVar[str] = "aws_waf_rate_based_statement_custom_key"
    mapping: ClassVar[Dict[str, Bender]] = {
        "header": S("Header") >> Bend(AwsWafRateLimit.mapping),
        "cookie": S("Cookie") >> Bend(AwsWafRateLimit.mapping),
        "query_argument": S("QueryArgument") >> Bend(AwsWafRateLimit.mapping),
        "query_string": S("QueryString") >> Bend(AwsWafRateLimit.mapping),
        "http_method": S("HTTPMethod"),
        "forwarded_ip": S("ForwardedIP"),
        "ip": S("IP"),
        "label_namespace": S("LabelNamespace", "Namespace"),
        "uri_path": S("UriPath") >> Bend(AwsWafRateLimitUriPath.mapping),
    }
    header: Optional[AwsWafRateLimit] = field(default=None, metadata={"description": "Use the value of a header in the request as an aggregate key. Each distinct value in the header contributes to the aggregation instance."})  # fmt: skip
    cookie: Optional[AwsWafRateLimit] = field(default=None, metadata={"description": "Use the value of a cookie in the request as an aggregate key. Each distinct value in the cookie contributes to the aggregation instance."})  # fmt: skip
    query_argument: Optional[AwsWafRateLimit] = field(default=None, metadata={"description": "Use the specified query argument as an aggregate key. Each distinct value for the named query argument contributes to the aggregation instance."})  # fmt: skip
    query_string: Optional[AwsWafRateLimit] = field(default=None, metadata={"description": "Use the request's query string as an aggregate key. Each distinct string contributes to the aggregation instance."})  # fmt: skip
    http_method: Optional[Json] = field(default=None, metadata={"description": "Use the request's HTTP method as an aggregate key. Each distinct HTTP method contributes to the aggregation instance."})  # fmt: skip
    forwarded_ip: Optional[Json] = field(default=None, metadata={"description": "Use the first IP address in an HTTP header as an aggregate key. Each distinct forwarded IP address contributes to the aggregation instance."})  # fmt: skip
    ip: Optional[Json] = field(default=None, metadata={"description": "Use the request's originating IP address as an aggregate key. Each distinct IP address contributes to the aggregation instance."})  # fmt: skip
    label_namespace: Optional[str] = field(default=None, metadata={"description": "Use the specified label namespace as an aggregate key. Each distinct fully qualified label name that has the specified label namespace contributes to the aggregation instance."})  # fmt: skip
    uri_path: Optional[AwsWafRateLimitUriPath] = field(default=None, metadata={"description": "Use the request's URI path as an aggregate key. Each distinct URI path contributes to the aggregation instance."})  # fmt: skip


def aws_waf_statement() -> Bender:
    # original: return AwsWafStatement.mapping, which leads to circular references
    return ParseJson(keys_to_snake=True)


@define(eq=False, slots=False)
class AwsWafRateBasedStatement:
    kind: ClassVar[str] = "aws_waf_rate_based_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "limit": S("Limit"),
        "aggregate_key_type": S("AggregateKeyType"),
        "scope_down_statement": S("ScopeDownStatement") >> Bend(aws_waf_statement()),
        "forwarded_ip_config": S("ForwardedIPConfig") >> Bend(AwsWafForwardedIPConfig.mapping),
        "custom_keys": S("CustomKeys", default=[]) >> ForallBend(AwsWafRateBasedStatementCustomKey.mapping),
    }
    limit: Optional[int] = field(default=None, metadata={"description": "The limit on requests per 5-minute period for a single aggregation instance for the rate-based rule."})  # fmt: skip
    aggregate_key_type: Optional[str] = field(default=None, metadata={"description": "Setting that indicates how to aggregate the request counts."})  # fmt: skip
    scope_down_statement: Optional[AwsWafStatement] = field(default=None, metadata={"description": "An optional nested statement that narrows the scope of the web requests that are evaluated and managed by the rate-based statement."})  # fmt: skip
    forwarded_ip_config: Optional[AwsWafForwardedIPConfig] = field(default=None, metadata={"description": "The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin."})  # fmt: skip
    custom_keys: Optional[List[AwsWafRateBasedStatementCustomKey]] = field(factory=list, metadata={"description": "Specifies the aggregate keys to use in a rate-base rule."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafAndStatement:
    kind: ClassVar[str] = "aws_waf_and_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "statements": S("Statements", default=[]) >> ForallBend(aws_waf_statement())
    }
    statements: Optional[List[AwsWafStatement]] = field(factory=list, metadata={"description": "The statements to combine with AND logic. You can use any statements that can be nested."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafOrStatement:
    kind: ClassVar[str] = "aws_waf_or_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "statements": S("Statements", default=[]) >> ForallBend(aws_waf_statement())
    }
    statements: Optional[List[AwsWafStatement]] = field(factory=list, metadata={"description": "The statements to combine with OR logic. You can use any statements that can be nested."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafNotStatement:
    kind: ClassVar[str] = "aws_waf_not_statement"
    mapping: ClassVar[Dict[str, Bender]] = {"statement": S("Statement") >> Bend(aws_waf_statement())}
    statement: Optional[AwsWafStatement] = field(default=None, metadata={"description": "The statement to negate. You can use any statement that can be nested."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafAWSManagedRulesBotControlRuleSet:
    kind: ClassVar[str] = "aws_waf_aws_managed_rules_bot_control_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "inspection_level": S("InspectionLevel"),
        "enable_machine_learning": S("EnableMachineLearning"),
    }
    inspection_level: Optional[str] = field(default=None, metadata={"description": "The inspection level to use for the Bot Control rule group. The common level is the least expensive."})  # fmt: skip
    enable_machine_learning: Optional[bool] = field(default=None, metadata={"description": "Applies only to the targeted inspection level."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRequestInspection:
    kind: ClassVar[str] = "aws_waf_request_inspection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "payload_type": S("PayloadType"),
        "username_field": S("UsernameField", "Identifier"),
        "password_field": S("PasswordField", "Identifier"),
    }
    payload_type: Optional[str] = field(default=None, metadata={"description": "The payload type for your login endpoint, either JSON or form encoded."})  # fmt: skip
    username_field: Optional[str] = field(default=None, metadata={"description": "The name of the field in the request payload that contains your customer's username."})  # fmt: skip
    password_field: Optional[str] = field(default=None, metadata={"description": "The name of the field in the request payload that contains your customer's password."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafResponseInspectionPart:
    kind: ClassVar[str] = "aws_waf_response_inspection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "identifier": S("Identifier"),
        "success_values": S("SuccessValues", default=[]),
        "failure_values": S("FailureValues", default=[]),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the header to match against."})  # fmt: skip
    identifier: Optional[str] = field(default=None, metadata={"description": "The identifier for the value to match against in the JSON."})  # fmt: skip
    success_values: Optional[List[str]] = field(factory=list, metadata={"description": "Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt."})  # fmt: skip
    failure_values: Optional[List[str]] = field(factory=list, metadata={"description": "Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafResponseInspection:
    kind: ClassVar[str] = "aws_waf_response_inspection"
    mapping: ClassVar[Dict[str, Bender]] = {
        "status_code": S("StatusCode") >> Bend(AwsWafResponseInspectionPart.mapping),
        "header": S("Header") >> Bend(AwsWafResponseInspectionPart.mapping),
        "body_contains": S("BodyContains") >> Bend(AwsWafResponseInspectionPart.mapping),
        "json": S("Json") >> Bend(AwsWafResponseInspectionPart.mapping),
    }
    status_code: Optional[AwsWafResponseInspectionPart] = field(default=None, metadata={"description": "Configures inspection of the response status code for success and failure indicators."})  # fmt: skip
    header: Optional[AwsWafResponseInspectionPart] = field(default=None, metadata={"description": "Configures inspection of the response header for success and failure indicators."})  # fmt: skip
    body_contains: Optional[AwsWafResponseInspectionPart] = field(default=None, metadata={"description": "Configures inspection of the response body for success and failure indicators."})  # fmt: skip
    json: Optional[AwsWafResponseInspectionPart] = field(default=None, metadata={"description": "Configures inspection of the response JSON for success and failure indicators."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafAWSManagedRulesATPRuleSet:
    kind: ClassVar[str] = "aws_waf_aws_managed_rules_atp_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "login_path": S("LoginPath"),
        "request_inspection": S("RequestInspection") >> Bend(AwsWafRequestInspection.mapping),
        "response_inspection": S("ResponseInspection") >> Bend(AwsWafResponseInspection.mapping),
        "enable_regex_in_path": S("EnableRegexInPath"),
    }
    login_path: Optional[str] = field(default=None, metadata={"description": "The path of the login endpoint for your application."})  # fmt: skip
    request_inspection: Optional[AwsWafRequestInspection] = field(default=None, metadata={"description": "The criteria for inspecting login requests, used by the ATP rule group to validate credentials usage."})  # fmt: skip
    response_inspection: Optional[AwsWafResponseInspection] = field(default=None, metadata={"description": "The criteria for inspecting responses to login requests, used by the ATP rule group to track login failure rates."})  # fmt: skip
    enable_regex_in_path: Optional[bool] = field(default=None, metadata={"description": "Allow the use of regular expressions in the login page path."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRequestInspectionACFP:
    kind: ClassVar[str] = "aws_waf_request_inspection_acfp"
    mapping: ClassVar[Dict[str, Bender]] = {
        "payload_type": S("PayloadType"),
        "username_field": S("UsernameField", "Identifier"),
        "password_field": S("PasswordField", "Identifier"),
        "email_field": S("EmailField", "Identifier"),
        "phone_number_fields": S("PhoneNumberFields", default=[]) >> ForallBend(S("Identifier")),
        "address_fields": S("AddressFields", default=[]) >> ForallBend(S("Identifier")),
    }
    payload_type: Optional[str] = field(default=None, metadata={"description": "The payload type for your account creation endpoint, either JSON or form encoded."})  # fmt: skip
    username_field: Optional[str] = field(default=None, metadata={"description": "The name of the field in the request payload that contains your customer's username."})  # fmt: skip
    password_field: Optional[str] = field(default=None, metadata={"description": "The name of the field in the request payload that contains your customer's password."})  # fmt: skip
    email_field: Optional[str] = field(default=None, metadata={"description": "The name of the field in the request payload that contains your customer's email."})  # fmt: skip
    phone_number_fields: Optional[List[str]] = field(factory=list, metadata={"description": "The names of the fields in the request payload that contain your customer's primary phone number."})  # fmt: skip
    address_fields: Optional[List[str]] = field(factory=list, metadata={"description": "The names of the fields in the request payload that contain your customer's primary physical address."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafAWSManagedRulesACFPRuleSet:
    kind: ClassVar[str] = "aws_waf_aws_managed_rules_acfp_rule_set"
    mapping: ClassVar[Dict[str, Bender]] = {
        "creation_path": S("CreationPath"),
        "registration_page_path": S("RegistrationPagePath"),
        "request_inspection": S("RequestInspection") >> Bend(AwsWafRequestInspectionACFP.mapping),
        "response_inspection": S("ResponseInspection") >> Bend(AwsWafResponseInspection.mapping),
        "enable_regex_in_path": S("EnableRegexInPath"),
    }
    creation_path: Optional[str] = field(default=None, metadata={"description": "The path of the account creation endpoint for your application."})  # fmt: skip
    registration_page_path: Optional[str] = field(default=None, metadata={"description": "The path of the account registration endpoint for your application."})  # fmt: skip
    request_inspection: Optional[AwsWafRequestInspectionACFP] = field(default=None, metadata={"description": "The criteria for inspecting account creation requests, used by the ACFP rule group to validate and track account creation attempts."})  # fmt: skip
    response_inspection: Optional[AwsWafResponseInspection] = field(default=None, metadata={"description": "The criteria for inspecting responses to account creation requests, used by the ACFP rule group to track account creation success rates. "})  # fmt: skip
    enable_regex_in_path: Optional[bool] = field(default=None, metadata={"description": "Allow the use of regular expressions in the registration page path and the account creation path."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafManagedRuleGroupConfig:
    kind: ClassVar[str] = "aws_waf_managed_rule_group_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "login_path": S("LoginPath"),
        "payload_type": S("PayloadType"),
        "username_field": S("UsernameField", "Identifier"),
        "password_field": S("PasswordField", "Identifier"),
        "aws_managed_rules_bot_control_rule_set": S("AWSManagedRulesBotControlRuleSet")
        >> Bend(AwsWafAWSManagedRulesBotControlRuleSet.mapping),
        "aws_managed_rules_atp_rule_set": S("AWSManagedRulesATPRuleSet")
        >> Bend(AwsWafAWSManagedRulesATPRuleSet.mapping),
        "aws_managed_rules_acfp_rule_set": S("AWSManagedRulesACFPRuleSet")
        >> Bend(AwsWafAWSManagedRulesACFPRuleSet.mapping),
    }
    login_path: Optional[str] = field(default=None, metadata={"description": "Instead of this setting, provide your configuration under AWSManagedRulesATPRuleSet."})  # fmt: skip
    payload_type: Optional[str] = field(default=None, metadata={"description": "Instead of this setting, provide your configuration under the request inspection configuration for AWSManagedRulesATPRuleSet or AWSManagedRulesACFPRuleSet."})  # fmt: skip
    username_field: Optional[str] = field(default=None, metadata={"description": "Instead of this setting, provide your configuration under the request inspection configuration for AWSManagedRulesATPRuleSet or AWSManagedRulesACFPRuleSet."})  # fmt: skip
    password_field: Optional[str] = field(default=None, metadata={"description": "Instead of this setting, provide your configuration under the request inspection configuration for AWSManagedRulesATPRuleSet or AWSManagedRulesACFPRuleSet."})  # fmt: skip
    aws_managed_rules_bot_control_rule_set: Optional[AwsWafAWSManagedRulesBotControlRuleSet] = field(default=None, metadata={"description": "Additional configuration for using the Bot Control managed rule group."})  # fmt: skip
    aws_managed_rules_atp_rule_set: Optional[AwsWafAWSManagedRulesATPRuleSet] = field(default=None, metadata={"description": "Additional configuration for using the account takeover prevention (ATP) managed rule group, AWSManagedRulesATPRuleSet."})  # fmt: skip
    aws_managed_rules_acfp_rule_set: Optional[AwsWafAWSManagedRulesACFPRuleSet] = field(default=None, metadata={"description": "Additional configuration for using the account creation fraud prevention (ACFP) managed rule group, AWSManagedRulesACFPRuleSet."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafManagedRuleGroupStatement:
    kind: ClassVar[str] = "aws_waf_managed_rule_group_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "vendor_name": S("VendorName"),
        "name": S("Name"),
        "version": S("Version"),
        "excluded_rules": S("ExcludedRules", default=[]) >> ForallBend(S("Name")),
        "scope_down_statement": S("ScopeDownStatement") >> Bend(aws_waf_statement()),
        "managed_rule_group_configs": S("ManagedRuleGroupConfigs", default=[])
        >> ForallBend(AwsWafManagedRuleGroupConfig.mapping),
        "rule_action_overrides": S("RuleActionOverrides", default=[]) >> ForallBend(AwsWafRuleActionOverride.mapping),
    }
    vendor_name: Optional[str] = field(default=None, metadata={"description": "The name of the managed rule group vendor."})  # fmt: skip
    name: Optional[str] = field(default=None, metadata={"description": "The name of the managed rule group."})  # fmt: skip
    version: Optional[str] = field(default=None, metadata={"description": "The version of the managed rule group to use."})  # fmt: skip
    excluded_rules: Optional[List[str]] = field(factory=list, metadata={"description": "Rules in the referenced rule group whose actions are set to Count."})  # fmt: skip
    scope_down_statement: Optional[AwsWafStatement] = field(default=None, metadata={"description": "An optional nested statement that narrows the scope of the web requests that are evaluated by the managed rule group."})  # fmt: skip
    managed_rule_group_configs: Optional[List[AwsWafManagedRuleGroupConfig]] = field(factory=list, metadata={"description": "Additional information that's used by a managed rule group. Many managed rule groups don't require this."})  # fmt: skip
    rule_action_overrides: Optional[List[AwsWafRuleActionOverride]] = field(factory=list, metadata={"description": "Action settings to use in the place of the rule actions that are configured inside the rule group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafLabelMatchStatement:
    kind: ClassVar[str] = "aws_waf_label_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {"scope": S("Scope"), "key": S("Key")}
    scope: Optional[str] = field(default=None, metadata={"description": "Specify whether you want to match using the label name or just the namespace."})  # fmt: skip
    key: Optional[str] = field(default=None, metadata={"description": "The string to match against. The setting you provide for this depends on the match statement's Scope setting."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRegexMatchStatement:
    kind: ClassVar[str] = "aws_waf_regex_match_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "regex_string": S("RegexString"),
        "field_to_match": S("FieldToMatch") >> Bend(AwsWafFieldToMatch.mapping),
        "text_transformations": S("TextTransformations", default=[]) >> ForallBend(AwsWafTextTransformation.mapping),
    }
    regex_string: Optional[str] = field(default=None, metadata={"description": "The string representing the regular expression."})  # fmt: skip
    field_to_match: Optional[AwsWafFieldToMatch] = field(default=None, metadata={"description": "The part of the web request that you want WAF to inspect."})  # fmt: skip
    text_transformations: Optional[List[AwsWafTextTransformation]] = field(factory=list, metadata={"description": "Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafStatement:
    kind: ClassVar[str] = "aws_waf_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "byte_match_statement": S("ByteMatchStatement") >> Bend(AwsWafByteMatchStatement.mapping),
        "sqli_match_statement": S("SqliMatchStatement") >> Bend(AwsWafSqliMatchStatement.mapping),
        "xss_match_statement": S("XssMatchStatement") >> Bend(AwsWafXssMatchStatement.mapping),
        "size_constraint_statement": S("SizeConstraintStatement") >> Bend(AwsWafSizeConstraintStatement.mapping),
        "geo_match_statement": S("GeoMatchStatement") >> Bend(AwsWafGeoMatchStatement.mapping),
        "rule_group_reference_statement": S("RuleGroupReferenceStatement")
        >> Bend(AwsWafRuleGroupReferenceStatement.mapping),
        "ip_set_reference_statement": S("IPSetReferenceStatement") >> Bend(AwsWafIPSetReferenceStatement.mapping),
        "regex_pattern_set_reference_statement": S("RegexPatternSetReferenceStatement")
        >> Bend(AwsWafRegexPatternSetReferenceStatement.mapping),
        "rate_based_statement": S("RateBasedStatement") >> Bend(AwsWafRateBasedStatement.mapping),
        "and_statement": S("AndStatement") >> Bend(AwsWafAndStatement.mapping),
        "or_statement": S("OrStatement") >> Bend(AwsWafOrStatement.mapping),
        "not_statement": S("NotStatement") >> Bend(AwsWafNotStatement.mapping),
        "managed_rule_group_statement": S("ManagedRuleGroupStatement") >> Bend(AwsWafManagedRuleGroupStatement.mapping),
        "label_match_statement": S("LabelMatchStatement") >> Bend(AwsWafLabelMatchStatement.mapping),
        "regex_match_statement": S("RegexMatchStatement") >> Bend(AwsWafRegexMatchStatement.mapping),
    }
    byte_match_statement: Optional[AwsWafByteMatchStatement] = field(default=None, metadata={"description": "A rule statement that defines a string match search for WAF to apply to web requests."})  # fmt: skip
    sqli_match_statement: Optional[AwsWafSqliMatchStatement] = field(default=None, metadata={"description": "A rule statement that inspects for malicious SQL code."})  # fmt: skip
    xss_match_statement: Optional[AwsWafXssMatchStatement] = field(default=None, metadata={"description": "A rule statement that inspects for cross-site scripting (XSS) attacks."})  # fmt: skip
    size_constraint_statement: Optional[AwsWafSizeConstraintStatement] = field(default=None, metadata={"description": "A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<). "})  # fmt: skip
    geo_match_statement: Optional[AwsWafGeoMatchStatement] = field(default=None, metadata={"description": "A rule statement that labels web requests by country and region and that matches against web requests based on country code."})  # fmt: skip
    rule_group_reference_statement: Optional[AwsWafRuleGroupReferenceStatement] = field(default=None, metadata={"description": "A rule statement used to run the rules that are defined in a RuleGroup."})  # fmt: skip
    ip_set_reference_statement: Optional[AwsWafIPSetReferenceStatement] = field(default=None, metadata={"description": "A rule statement used to detect web requests coming from particular IP addresses or address ranges."})  # fmt: skip
    regex_pattern_set_reference_statement: Optional[AwsWafRegexPatternSetReferenceStatement] = field(default=None, metadata={"description": "A rule statement used to search web request components for matches with regular expressions."})  # fmt: skip
    rate_based_statement: Optional[AwsWafRateBasedStatement] = field(default=None, metadata={"description": "A rate-based rule counts incoming requests and rate limits requests when they are coming at too fast a rate."})  # fmt: skip
    and_statement: Optional[AwsWafAndStatement] = field(default=None, metadata={"description": "A logical rule statement used to combine other rule statements with AND logic. You provide more than one Statement within the AndStatement."})  # fmt: skip
    or_statement: Optional[AwsWafOrStatement] = field(default=None, metadata={"description": "A logical rule statement used to combine other rule statements with OR logic. You provide more than one Statement within the OrStatement."})  # fmt: skip
    not_statement: Optional[AwsWafNotStatement] = field(default=None, metadata={"description": "A logical rule statement used to negate the results of another rule statement. You provide one Statement within the NotStatement."})  # fmt: skip
    managed_rule_group_statement: Optional[AwsWafManagedRuleGroupStatement] = field(default=None, metadata={"description": "A rule statement used to run the rules that are defined in a managed rule group."})  # fmt: skip
    label_match_statement: Optional[AwsWafLabelMatchStatement] = field(default=None, metadata={"description": "A rule statement to match against labels that have been added to the web request by rules that have already run in the web ACL."})  # fmt: skip
    regex_match_statement: Optional[AwsWafRegexMatchStatement] = field(default=None, metadata={"description": "A rule statement used to search web request components for a match against a single regular expression."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafOverrideAction:
    kind: ClassVar[str] = "aws_waf_override_action"
    mapping: ClassVar[Dict[str, Bender]] = {"count": S("Count") >> Bend(AwsWafCountAction.mapping), "none": S("None")}
    count: Optional[AwsWafCountAction] = field(default=None, metadata={"description": "Override the rule group evaluation result to count only."})  # fmt: skip
    none: Optional[Json] = field(default=None, metadata={"description": "Don't override the rule group evaluation result. This is the most common setting."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafVisibilityConfig:
    kind: ClassVar[str] = "aws_waf_visibility_config"
    mapping: ClassVar[Dict[str, Bender]] = {
        "sampled_requests_enabled": S("SampledRequestsEnabled"),
        "cloud_watch_metrics_enabled": S("CloudWatchMetricsEnabled"),
        "metric_name": S("MetricName"),
    }
    sampled_requests_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether WAF should store a sampling of the web requests that match the rules."})  # fmt: skip
    cloud_watch_metrics_enabled: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the associated resource sends metrics to Amazon CloudWatch."})  # fmt: skip
    metric_name: Optional[str] = field(default=None, metadata={"description": "A name of the Amazon CloudWatch metric dimension."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCaptchaConfig:
    kind: ClassVar[str] = "aws_waf_captcha_config"
    mapping: ClassVar[Dict[str, Bender]] = {"immunity_time_property": S("ImmunityTimeProperty", "ImmunityTime")}
    immunity_time_property: Optional[int] = field(default=None, metadata={"description": "Determines how long a CAPTCHA timestamp in the token remains valid after the client successfully solves a CAPTCHA puzzle."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafChallengeConfig:
    kind: ClassVar[str] = "aws_waf_challenge_config"
    mapping: ClassVar[Dict[str, Bender]] = {"immunity_time_property": S("ImmunityTimeProperty", "ImmunityTime")}
    immunity_time_property: Optional[int] = field(default=None, metadata={"description": "Determines how long a challenge timestamp in the token remains valid after the client successfully responds to a challenge."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafRule:
    kind: ClassVar[str] = "aws_waf_rule"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "priority": S("Priority"),
        "statement": S("Statement") >> Bend(AwsWafStatement.mapping),
        "action": S("Action") >> Bend(AwsWafRuleAction.mapping),
        "override_action": S("OverrideAction") >> Bend(AwsWafOverrideAction.mapping),
        "rule_labels": S("RuleLabels", default=[]) >> ForallBend(S("Name")),
        "visibility_config": S("VisibilityConfig") >> Bend(AwsWafVisibilityConfig.mapping),
        "captcha_config": S("CaptchaConfig") >> Bend(AwsWafCaptchaConfig.mapping),
        "challenge_config": S("ChallengeConfig") >> Bend(AwsWafChallengeConfig.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the rule."})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={"description": "If you define more than one Rule in a WebACL, WAF evaluates each request against the Rules in order based on the value of Priority."})  # fmt: skip
    statement: Optional[AwsWafStatement] = field(default=None, metadata={"description": "The WAF processing statement for the rule, for example ByteMatchStatement or SizeConstraintStatement."})  # fmt: skip
    action: Optional[AwsWafRuleAction] = field(default=None, metadata={"description": "The action that WAF should take on a web request when it matches the rule statement."})  # fmt: skip
    override_action: Optional[AwsWafOverrideAction] = field(default=None, metadata={"description": "The action to use in the place of the action that results from the rule group evaluation."})  # fmt: skip
    rule_labels: Optional[List[str]] = field(factory=list, metadata={"description": "Labels to apply to web requests that match the rule match statement."})  # fmt: skip
    visibility_config: Optional[AwsWafVisibilityConfig] = field(default=None, metadata={"description": "Defines and enables Amazon CloudWatch metrics and web request sample collection."})  # fmt: skip
    captcha_config: Optional[AwsWafCaptchaConfig] = field(default=None, metadata={"description": "Specifies how WAF should handle CAPTCHA evaluations."})  # fmt: skip
    challenge_config: Optional[AwsWafChallengeConfig] = field(default=None, metadata={"description": "Specifies how WAF should handle Challenge evaluations."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafFirewallManagerStatement:
    kind: ClassVar[str] = "aws_waf_firewall_manager_statement"
    mapping: ClassVar[Dict[str, Bender]] = {
        "managed_rule_group_statement": S("ManagedRuleGroupStatement") >> Bend(AwsWafManagedRuleGroupStatement.mapping),
        "rule_group_reference_statement": S("RuleGroupReferenceStatement")
        >> Bend(AwsWafRuleGroupReferenceStatement.mapping),
    }
    managed_rule_group_statement: Optional[AwsWafManagedRuleGroupStatement] = field(default=None, metadata={"description": "A statement used by Firewall Manager to run the rules that are defined in a managed rule group."})  # fmt: skip
    rule_group_reference_statement: Optional[AwsWafRuleGroupReferenceStatement] = field(default=None, metadata={"description": "A statement used by Firewall Manager to run the rules that are defined in a rule group."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafFirewallManagerRuleGroup:
    kind: ClassVar[str] = "aws_waf_firewall_manager_rule_group"
    mapping: ClassVar[Dict[str, Bender]] = {
        "name": S("Name"),
        "priority": S("Priority"),
        "firewall_manager_statement": S("FirewallManagerStatement") >> Bend(AwsWafFirewallManagerStatement.mapping),
        "override_action": S("OverrideAction") >> Bend(AwsWafOverrideAction.mapping),
        "visibility_config": S("VisibilityConfig") >> Bend(AwsWafVisibilityConfig.mapping),
    }
    name: Optional[str] = field(default=None, metadata={"description": "The name of the rule group. You cannot change the name of a rule group after you create it."})  # fmt: skip
    priority: Optional[int] = field(default=None, metadata={"description": "If you define more than one rule group in the first or last Firewall Manager rule groups, WAF evaluates each request against the rule groups in order, starting from the lowest priority setting."})  # fmt: skip
    firewall_manager_statement: Optional[AwsWafFirewallManagerStatement] = field(default=None, metadata={"description": "The processing guidance for an Firewall Manager rule"})  # fmt: skip
    override_action: Optional[AwsWafOverrideAction] = field(default=None, metadata={"description": "The action to use in the place of the action that results from the rule group evaluation."})  # fmt: skip
    visibility_config: Optional[AwsWafVisibilityConfig] = field(default=None, metadata={"description": "Defines and enables Amazon CloudWatch metrics and web request sample collection."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCustomResponseBody:
    kind: ClassVar[str] = "aws_waf_custom_response_body"
    mapping: ClassVar[Dict[str, Bender]] = {"content_type": S("ContentType"), "content": S("Content")}
    content_type: Optional[str] = field(default=None, metadata={"description": "The type of content in the payload that you are defining in the Content string."})  # fmt: skip
    content: Optional[str] = field(default=None, metadata={"description": "The payload of the custom response."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafCondition:
    kind: ClassVar[str] = "aws_waf_condition"
    mapping: ClassVar[Dict[str, Bender]] = {
        "action_condition": S("ActionCondition", "Action"),
        "label_name_condition": S("LabelNameCondition", "LabelName"),
    }
    action_condition: Optional[str] = field(default=None, metadata={"description": "A single action condition. This is the action setting that a log record must contain in order to meet the condition."})  # fmt: skip
    label_name_condition: Optional[str] = field(default=None, metadata={"description": "A single label name condition. This is the fully qualified label name that a log record must contain in order to meet the condition. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafFilter:
    kind: ClassVar[str] = "aws_waf_filter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "behavior": S("Behavior"),
        "requirement": S("Requirement"),
        "conditions": S("Conditions", default=[]) >> ForallBend(AwsWafCondition.mapping),
    }
    behavior: Optional[str] = field(default=None, metadata={"description": "How to handle logs that satisfy the filter's conditions and requirement."})  # fmt: skip
    requirement: Optional[str] = field(default=None, metadata={"description": "Logic to apply to the filtering conditions. You can specify that, in order to satisfy the filter, a log must match all conditions or must match at least one condition."})  # fmt: skip
    conditions: Optional[List[AwsWafCondition]] = field(factory=list, metadata={"description": "Match conditions for the filter."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafLoggingFilter:
    kind: ClassVar[str] = "aws_waf_logging_filter"
    mapping: ClassVar[Dict[str, Bender]] = {
        "filters": S("Filters", default=[]) >> ForallBend(AwsWafFilter.mapping),
        "default_behavior": S("DefaultBehavior"),
    }
    filters: Optional[List[AwsWafFilter]] = field(factory=list, metadata={"description": "The filters that you want to apply to the logs."})  # fmt: skip
    default_behavior: Optional[str] = field(default=None, metadata={"description": "Default handling for logs that don't match any of the specified filtering conditions."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafLoggingConfiguration:
    kind: ClassVar[str] = "aws_waf_logging_configuration"
    mapping: ClassVar[Dict[str, Bender]] = {
        "log_destination_configs": S("LogDestinationConfigs", default=[]),
        "redacted_fields": S("RedactedFields", default=[]) >> ForallBend(AwsWafFieldToMatch.mapping),
        "managed_by_firewall_manager": S("ManagedByFirewallManager"),
        "logging_filter": S("LoggingFilter") >> Bend(AwsWafLoggingFilter.mapping),
    }
    log_destination_configs: Optional[List[str]] = field(factory=list, metadata={"description": "The logging destination configuration that you want to associate with the web ACL.  You can associate one logging destination to a web ACL."})  # fmt: skip
    redacted_fields: Optional[List[AwsWafFieldToMatch]] = field(factory=list, metadata={"description": "The parts of the request that you want to keep out of the logs. For example, if you redact the SingleHeader field, the HEADER field in the logs will be REDACTED for all rules that use the SingleHeader FieldToMatch setting.  Redaction applies only to the component that's specified in the rule's FieldToMatch setting, so the SingleHeader redaction doesn't apply to rules that use the Headers FieldToMatch.  You can specify only the following fields for redaction: UriPath, QueryString, SingleHeader, and Method."})  # fmt: skip
    managed_by_firewall_manager: Optional[bool] = field(default=None, metadata={"description": "Indicates whether the logging configuration was created by Firewall Manager, as part of an WAF policy configuration. If true, only Firewall Manager can modify or delete the configuration."})  # fmt: skip
    logging_filter: Optional[AwsWafLoggingFilter] = field(default=None, metadata={"description": "Filtering that specifies which web requests are kept in the logs and which are dropped. You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation."})  # fmt: skip


@define(eq=False, slots=False)
class AwsWafWebACL(AwsResource):
    kind: ClassVar[str] = "aws_waf_web_acl"
    kind_display: ClassVar[str] = "AWS WAF Web ACL"
    kind_description: ClassVar[str] = "An AWS WAF Web ACL (Web Access Control List) is used for monitoring HTTP and HTTPS requests directed to AWS resources, allowing you to control access by permitting or blocking specific requests based on defined criteria."  # fmt: skip
    aws_metadata: ClassVar[Dict[str, Any]] = {"provider_link_tpl": "https://{region_id}.console.aws.amazon.com/wafv2/homev2/web-acl/{name}/{id}/overview?region={region}", "arn_tpl": "arn:{partition}:wafv2:{region}:{account}:webacl/{id}"}  # fmt: skip
    api_spec: ClassVar[AwsApiSpec] = AwsApiSpec("wafv2", "get-web-acl", "WebACL")
    reference_kinds: ClassVar[ModelReference] = {
        "successors": {"default": ["aws_alb", "aws_apigateway_rest_api", "aws_cognito_user_pool"]}
    }
    mapping: ClassVar[Dict[str, Bender]] = {
        "id": S("Id"),
        "name": S("Name"),
        "tags": S("Tags", default=[]) >> ToDict(),
        "arn": S("ARN"),
        "default_action": S("DefaultAction") >> Bend(AwsWafDefaultAction.mapping),
        "description": S("Description"),
        "waf_rules": S("Rules", default=[]) >> ForallBend(AwsWafRule.mapping),
        "visibility_config": S("VisibilityConfig") >> Bend(AwsWafVisibilityConfig.mapping),
        "capacity": S("Capacity"),
        "pre_process_firewall_manager_rule_groups": S("PreProcessFirewallManagerRuleGroups", default=[])
        >> ForallBend(AwsWafFirewallManagerRuleGroup.mapping),
        "post_process_firewall_manager_rule_groups": S("PostProcessFirewallManagerRuleGroups", default=[])
        >> ForallBend(AwsWafFirewallManagerRuleGroup.mapping),
        "managed_by_firewall_manager": S("ManagedByFirewallManager"),
        "label_namespace": S("LabelNamespace"),
        "custom_response_bodies": S("CustomResponseBodies")
        >> MapDict(value_bender=Bend(AwsWafCustomResponseBody.mapping)),
        "captcha_config": S("CaptchaConfig") >> Bend(AwsWafCaptchaConfig.mapping),
        "challenge_config": S("ChallengeConfig") >> Bend(AwsWafChallengeConfig.mapping),
        "token_domains": S("TokenDomains", default=[]),
        "association_inspection_limit": S("AssociationConfig", "RequestBody", "DefaultSizeInspectionLimit"),
    }
    default_action: Optional[AwsWafDefaultAction] = field(default=None, metadata={"description": "The action to perform if none of the Rules contained in the WebACL match."})  # fmt: skip
    description: Optional[str] = field(default=None, metadata={"description": "A description of the web ACL that helps with identification."})  # fmt: skip
    rules: Optional[List[AwsWafRule]] = field(factory=list, metadata={"description": "The Rule statements used to identify the web requests that you want to manage. Each rule includes one top-level statement that WAF uses to identify matching web requests, and parameters that govern how WAF handles them."})  # fmt: skip
    visibility_config: Optional[AwsWafVisibilityConfig] = field(default=None, metadata={"description": "Defines and enables Amazon CloudWatch metrics and web request sample collection."})  # fmt: skip
    capacity: Optional[int] = field(default=None, metadata={"description": "The web ACL capacity units (WCUs) currently being used by this web ACL.  WAF uses WCUs to calculate and control the operating resources that are used to run your rules, rule groups, and web ACLs."})  # fmt: skip
    pre_process_firewall_manager_rule_groups: Optional[List[AwsWafFirewallManagerRuleGroup]] = field(factory=list, metadata={"description": "The first set of rules for WAF to process in the web ACL."})  # fmt: skip
    post_process_firewall_manager_rule_groups: Optional[List[AwsWafFirewallManagerRuleGroup]] = field(factory=list, metadata={"description": "The last set of rules for WAF to process in the web ACL."})  # fmt: skip
    managed_by_firewall_manager: Optional[bool] = field(default=None, metadata={"description": "Indicates whether this web ACL is managed by Firewall Manager. If true, then only Firewall Manager can delete the web ACL or any Firewall Manager rule groups in the web ACL."})  # fmt: skip
    label_namespace: Optional[str] = field(default=None, metadata={"description": "The label namespace prefix for this web ACL. All labels added by rules in this web ACL have this prefix."})  # fmt: skip
    custom_response_bodies: Optional[Dict[str, AwsWafCustomResponseBody]] = field(default=None, metadata={"description": "A map of custom response keys and content bodies."})  # fmt: skip
    captcha_config: Optional[AwsWafCaptchaConfig] = field(default=None, metadata={"description": "Specifies how WAF should handle CAPTCHA evaluations for rules that don't have their own CaptchaConfig settings."})  # fmt: skip
    challenge_config: Optional[AwsWafChallengeConfig] = field(default=None, metadata={"description": "Specifies how WAF should handle challenge evaluations for rules that don't have their own ChallengeConfig settings."})  # fmt: skip
    token_domains: Optional[List[str]] = field(factory=list, metadata={"description": "Specifies the domains that WAF should accept in a web request token. This enables the use of tokens across multiple protected websites."})  # fmt: skip
    association_inspection_limit: Optional[str] = field(default=None, metadata={"description": "Specifies the maximum size of the web request body component that an associated CloudFront distribution should send to WAF for inspection."})  # fmt: skip
    logging_configuration: Optional[AwsWafLoggingConfiguration] = None
    _associated_resources: Optional[List[str]] = None

    @classmethod
    def collect_resources(cls: Type[AwsResource], builder: GraphBuilder) -> None:
        def fetch_acl_resources(acl: AwsWafWebACL) -> None:
            with builder.suppress(f"{service_name}.list-resources-for-web-acl"):
                acl._associated_resources = builder.client.list(
                    service_name, "list-resources-for-web-acl", "ResourceArns", WebACLArn=acl.arn
                )

        def fetch_logging_configuration(acl: AwsWafWebACL) -> None:
            with builder.suppress(f"{service_name}.get-logging-configuration"):
                if logging_configuration := builder.client.get(
                    aws_service=service_name,
                    action="get-logging-configuration",
                    result_name="LoggingConfiguration",
                    expected_errors=["WAFNonexistentItemException"],
                    ResourceArn=acl.arn,
                ):
                    acl.logging_configuration = parse_json(
                        logging_configuration, AwsWafLoggingConfiguration, builder, AwsWafLoggingConfiguration.mapping
                    )

        def fetch_web_acl(entry: Json, scope: str) -> None:
            if web_acl := builder.client.get(
                aws_service=service_name,
                action="get-web-acl",
                result_name="WebACL",
                Scope=scope,
                Id=entry["Id"],
                Name=entry["Name"],
            ):
                if instance := AwsWafWebACL.from_api(web_acl, builder):
                    builder.add_node(instance, web_acl)
                    builder.submit_work(service_name, fetch_logging_configuration, instance)
                    if scope == "REGIONAL":  # only regional ACLs have associated resources
                        builder.submit_work(service_name, fetch_acl_resources, instance)

        # Default behavior: in case the class has an ApiSpec, call the api and call collect.
        log.debug(f"Collecting {cls.__name__} in region {builder.region.name}")
        try:
            for entry in builder.client.list(
                aws_service=service_name,
                action="list-web-acls",
                result_name="WebACLs",
                Scope="REGIONAL",
            ):
                builder.submit_work(service_name, fetch_web_acl, entry, "REGIONAL")
            for entry in builder.client.list(
                aws_service=service_name,
                action="list-web-acls",
                result_name="WebACLs",
                Scope="CLOUDFRONT",
            ):
                builder.submit_work(service_name, fetch_web_acl, entry, "CLOUDFRONT")
        except Boto3Error as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.error(msg, log)
            raise
        except Exception as e:
            msg = f"Error while collecting {cls.__name__} in region {builder.region.name}: {e}"
            builder.core_feedback.info(msg, log)
            raise

    def connect_in_graph(self, builder: GraphBuilder, source: Json) -> None:
        for arn in self._associated_resources or []:
            builder.add_edge(self, arn=arn)
        if (lc := self.logging_configuration) and (lcdcs := lc.log_destination_configs):
            for arn in lcdcs:
                builder.add_edge(self, arn=arn)

    @classmethod
    def called_collect_apis(cls) -> List[AwsApiSpec]:
        return [
            AwsApiSpec(service_name, "list-web-acls"),
            AwsApiSpec(service_name, "get-web-acl"),
            AwsApiSpec(service_name, "list-resources-for-web-acl"),
            AwsApiSpec(service_name, "get-logging-configuration"),
        ]


resources: List[Type[AwsResource]] = [AwsWafWebACL]
