# "BASE_ABAC" contains ABAC elements that are included in all
# user.yaml files
BASE_ABAC = {
    "groups": [],
    "anonymous_policies": ["open_reader"],
    "all_users_policies": ["open_reader"],
    "policies": [
        {
            "id": "data_upload",
            "description": "upload raw data files to S3 (for new data upload flow)",
            "resource_paths": ["/data_file"],
            "role_ids": ["file_uploader"],
        },
        {
            "id": "workspace",
            "description": "be able to use workspace",
            "resource_paths": ["/workspace"],
            "role_ids": ["workspace_user"],
        },
        {
            "id": "prometheus",
            "description": "be able to use prometheus",
            "resource_paths": ["/prometheus"],
            "role_ids": ["prometheus_user"],
        },
        {
            "id": "open_reader",
            "description": "",
            "role_ids": ["reader", "storage_reader"],
            "resource_paths": ["/open"],
        },
        {
            "id": "open_admin",
            "description": "",
            "role_ids": [
                "creator",
                "reader",
                "updater",
                "deleter",
                "storage_writer",
                "storage_reader",
            ],
            "resource_paths": ["/open"],
        },
    ],
    "resources": [
        {"name": "data_file", "description": "data files, stored in S3"},
        {"name": "workspace"},
        {"name": "prometheus"},
        {"name": "open"},
    ],
    "roles": [
        {
            "id": "file_uploader",
            "description": "can upload data files",
            "permissions": [
                {
                    "action": {"method": "file_upload", "service": "fence"},
                    "id": "file_upload",
                }
            ],
        },
        {
            "id": "workspace_user",
            "permissions": [
                {
                    "action": {"method": "access", "service": "jupyterhub"},
                    "id": "workspace_access",
                }
            ],
        },
        {
            "id": "prometheus_user",
            "permissions": [
                {
                    "action": {"method": "access", "service": "prometheus"},
                    "id": "prometheus_access",
                }
            ],
        },
    ],
}
