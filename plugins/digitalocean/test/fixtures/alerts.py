alerts = [
    {
        "uuid": "d916cb34-6ee3-48c0-bca5-3f3cc08db5d3",
        "type": "v1/insights/droplet/cpu",
        "description": "CPU is running high",
        "compare": "GreaterThan",
        "value": 70,
        "window": "5m",
        "entities": [],
        "tags": [],
        "alerts": {"slack": [], "email": ["alerts@example.com"]},
        "enabled": True,
    }
]
