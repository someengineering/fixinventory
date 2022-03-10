k8s = [
    {
        "id": "e1c48631-b382-4001-2168-c47c54795a26",
        "name": "k8s-1-22-7-do-0-fra1-test",
        "region": "fra1",
        "version": "1.22.7-do.0",
        "cluster_subnet": "10.244.0.0/16",
        "service_subnet": "10.245.0.0/16",
        "vpc_uuid": "0d3176ad-41e0-4021-b831-0c5c45c60959",
        "ipv4": "127.0.0.1",
        "endpoint": "https://e1c48631-b382-4001-2168-c47c54795a26.k8s.ondigitalocean.com",
        "tags": ["k8s", "k8s:e1c48631-b382-4001-2168-c47c54795a26"],
        "node_pools": [
            {
                "id": "486ac4dd-6672-4364-9138-8d7f26d131aa",
                "name": "pool-1g2g56zow",
                "size": "s-1vcpu-2gb",
                "count": 1,
                "tags": [
                    "k8s",
                    "k8s:e1c48631-b382-4001-2168-c47c54795a26",
                    "k8s:worker",
                ],
                "labels": None,
                "taints": [],
                "auto_scale": False,
                "min_nodes": 0,
                "max_nodes": 0,
                "nodes": [
                    {
                        "id": "cad9fd5a-c64e-464f-8711-e66eadb5bd44",
                        "name": "pool-1g2g56zow-u9fs4",
                        "status": {"state": "running"},
                        "droplet_id": "290075243",
                        "created_at": "2022-03-10T13:07:00Z",
                        "updated_at": "2022-03-10T13:11:29Z",
                    }
                ],
            }
        ],
        "maintenance_policy": {
            "start_time": "20:00",
            "duration": "4h0m0s",
            "day": "any",
        },
        "auto_upgrade": False,
        "status": {"state": "running"},
        "created_at": "2022-03-10T13:07:00Z",
        "updated_at": "2022-03-10T13:13:29Z",
        "surge_upgrade": True,
        "registry_enabled": False,
        "ha": False,
        "supported_features": [
            "cluster-autoscaler",
            "docr-integration",
            "token-authentication",
        ],
    },
]
