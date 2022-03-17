apps = [
    {
        "id": "5dc41512-7523-4eeb-9932-426aa570234b",
        "owner_uuid": "d63ae7cb6500140c46fdb3585b0c1a874e195760",
        "default_ingress": "https://resoto_test_app.ondigitalocean.app",
        "live_url": "https://resoto_test_app.ondigitalocean.app",
        "live_url_base": "https://resoto_test_app.ondigitalocean.app",
        "live_domain": "resoto_test_apps.ondigitalocean.app",
        "spec": {
            "name": "resoto-test-app",
            "services": [
                {
                    "name": "resoto-test-app",
                    "image": {
                        "registry_type": "DOCKER_HUB",
                        "registry": "grafana",
                        "repository": "alpine",
                        "tag": "3.15.0",
                    },
                    "source_dir": "/",
                    "envs": [
                        {
                            "key": "DATABASE_URL",
                            "value": "${db-postgresql-fra1-82725.DATABASE_URL}",
                            "scope": "RUN_TIME",
                        }
                    ],
                    "instance_size_slug": "basic-xxs",
                    "instance_count": 1,
                    "http_port": 8080,
                    "routes": [{"path": "/"}],
                }
            ],
            "databases": [
                {
                    "name": "db-postgresql-fra1-82725",
                    "engine": "PG",
                    "version": "14",
                    "production": True,
                    "cluster_name": "db-postgresql-fra1-82725",
                    "db_name": "defaultdb",
                    "db_user": "doadmin",
                }
            ],
            "region": "fra",
            "alerts": [{"rule": "DEPLOYMENT_FAILED"}, {"rule": "DOMAIN_FAILED"}],
        },
        "last_deployment_active_at": "2022-03-13T13:02:38Z",
        "created_at": "2022-03-13T12:53:13Z",
        "updated_at": "2022-03-13T13:04:42Z",
        "last_deployment_created_at": "2022-03-13T13:02:38Z",
        "region": {
            "slug": "fra",
            "label": "Frankfurt",
            "flag": "germany",
            "continent": "Europe",
            "data_centers": ["fra1"],
        },
        "tier_slug": "basic",
    },
]
