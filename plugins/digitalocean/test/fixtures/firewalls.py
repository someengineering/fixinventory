firewalls = [
    {
        "id": "fe2e76df-3e15-4895-800f-2d5b3b807711",
        "name": "k8s-fe2e76df-3e15-4895-800f-2d5b3b807711-worker",
        "status": "succeeded",
        "inbound_rules": [
            {
                "protocol": "icmp",
                "ports": "0",
                "sources": {"addresses": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
            },
            {
                "protocol": "tcp",
                "ports": "0",
                "sources": {"addresses": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
            },
            {
                "protocol": "udp",
                "ports": "0",
                "sources": {"addresses": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
            },
        ],
        "outbound_rules": [
            {
                "protocol": "icmp",
                "ports": "0",
                "destinations": {"addresses": ["0.0.0.0/0"]},
            },
            {
                "protocol": "tcp",
                "ports": "0",
                "destinations": {"addresses": ["0.0.0.0/0"]},
            },
            {
                "protocol": "udp",
                "ports": "0",
                "destinations": {"addresses": ["0.0.0.0/0"]},
            },
        ],
        "created_at": "2022-03-10T13:10:50Z",
        "droplet_ids": [289110074],
        "tags": ["firewall_tag"],
        "pending_changes": [],
    },
]
