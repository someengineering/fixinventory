from fix_plugin_aws.resource.bedrock import (
    AwsBedrockCustomModel,
    AwsBedrockProvisionedModelThroughput,
    AwsBedrockGuardrail,
    AwsBedrockModelCustomizationJob,
    AwsBedrockEvaluationJob,
    AwsBedrockAgent,
    AwsBedrockAgentPrompt,
    AwsBedrockAgentFlow,
    AwsBedrockFoundationModel,
)
from test.resources import round_trip_for


def test_bedrock_custom_models() -> None:
    round_trip_for(AwsBedrockCustomModel, ignore_checking_props=True)


def test_bedrock_provisioned_model_throughputs() -> None:
    round_trip_for(AwsBedrockProvisionedModelThroughput, ignore_checking_props=True)


def test_bedrock_guardrails() -> None:
    round_trip_for(AwsBedrockGuardrail, ignore_checking_props=True)


def test_bedrock_model_customization_jobs() -> None:
    round_trip_for(AwsBedrockModelCustomizationJob, ignore_checking_props=True)


def test_bedrock_evaluation_jobs() -> None:
    round_trip_for(AwsBedrockEvaluationJob, ignore_checking_props=True)


def test_bedrock_agents() -> None:
    round_trip_for(AwsBedrockAgent, ignore_checking_props=True)


def test_bedrock_agent_prompts() -> None:
    round_trip_for(AwsBedrockAgentPrompt, ignore_checking_props=True)


def test_bedrock_agent_flows() -> None:
    round_trip_for(AwsBedrockAgentFlow, ignore_checking_props=True)


def test_bedrock_foundation_model() -> None:
    round_trip_for(AwsBedrockFoundationModel, ignore_checking_props=True)
