import yaml

from .validation import validate_user_yaml


def convert_old_user_yaml_to_new_user_yaml(user_yaml):
    """
    Converts a user.yaml file to the new format required by the
    latest fence and arborist.

    Args:
        user_yaml (str): Contents of a user.yaml file.
    """

    # make sure the syntax is valid and expected fields exist
    # validate_user_yaml(user_yaml)

    old_user_yaml = yaml.safe_load(user_yaml)
    new_user_yaml = {
        "cloud_providers": old_user_yaml.get("cloud_providers", {}),
        "groups": old_user_yaml.get("groups", {}),
        "rbac": {
            "groups": [],
            "anonymous_policies": ["open_data_reader"],
            "all_users_policies": ["open_data_reader"],
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
            ],
            "resources": [
                {"name": "data_file", "description": "data files, stored in S3"},
                {"name": "workspace"},
                {"name": "prometheus"},
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
                {
                    "id": "admin",
                    "description": "",
                    "permissions": [
                        {"id": "admin", "action": {"service": "*", "method": "*"}}
                    ],
                },
                {
                    "id": "creator",
                    "description": "",
                    "permissions": [
                        {
                            "id": "creator",
                            "action": {"service": "*", "method": "create"},
                        }
                    ],
                },
                {
                    "id": "reader",
                    "description": "",
                    "permissions": [
                        {"id": "reader", "action": {"service": "*", "method": "read"}}
                    ],
                },
                {
                    "id": "updater",
                    "description": "",
                    "permissions": [
                        {
                            "id": "updater",
                            "action": {"service": "*", "method": "update"},
                        }
                    ],
                },
                {
                    "id": "deleter",
                    "description": "",
                    "permissions": [
                        {
                            "id": "deleter",
                            "action": {"service": "*", "method": "delete"},
                        }
                    ],
                },
                {
                    "id": "storage_writer",
                    "description": "",
                    "permissions": [
                        {
                            "id": "storage_creator",
                            "action": {"service": "*", "method": "write_storage"},
                        }
                    ],
                },
                {
                    "id": "storage_reader",
                    "description": "",
                    "permissions": [
                        {
                            "id": "storage_reader",
                            "action": {"service": "*", "method": "read_storage"},
                        }
                    ],
                },
                {
                    "id": "indexd_record_creator",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_record_creator",
                            "action": {"service": "indexd", "method": "create"},
                        }
                    ],
                },
                {
                    "id": "indexd_record_reader",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_record_reader",
                            "action": {"service": "indexd", "method": "read"},
                        }
                    ],
                },
                {
                    "id": "indexd_record_updater",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_record_updater",
                            "action": {"service": "indexd", "method": "update"},
                        }
                    ],
                },
                {
                    "id": "indexd_delete_record",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_delete_record",
                            "action": {"service": "indexd", "method": "delete"},
                        }
                    ],
                },
                {
                    "id": "indexd_storage_reader",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_storage_reader",
                            "action": {"service": "indexd", "method": "read_storage"},
                        }
                    ],
                },
                {
                    "id": "indexd_storage_writer",
                    "description": "",
                    "permissions": [
                        {
                            "id": "indexd_storage_writer",
                            "action": {"service": "indexd", "method": "write_storage"},
                        }
                    ],
                },
                {
                    "id": "arborist_creator",
                    "description": "",
                    "permissions": [
                        {
                            "id": "arborist_creator",
                            "action": {"service": "arborist", "method": "create"},
                        }
                    ],
                },
                {
                    "id": "arborist_reader",
                    "description": "",
                    "permissions": [
                        {
                            "id": "arborist_reader",
                            "action": {"service": "arborist", "method": "read"},
                        }
                    ],
                },
                {
                    "id": "arborist_updater",
                    "description": "",
                    "permissions": [
                        {
                            "id": "arborist_updater",
                            "action": {"service": "arborist", "method": "update"},
                        }
                    ],
                },
                {
                    "id": "arborist_deleter",
                    "description": "",
                    "permissions": [
                        {
                            "id": "arborist_deleter",
                            "action": {"service": "arborist", "method": "delete"},
                        }
                    ],
                },
            ],
        },
        "users": {},
    }

    existing_resources = [
        item.get("name") for item in new_user_yaml["rbac"]["resources"]
    ]
    old_resources = old_user_yaml.get("rbac", {}).get("resources", [])
    for resource in old_resources:
        if resource["name"] == "programs":
            # TODO: should this have prefix "gen3"?
            new_user_yaml["rbac"]["resources"].append(resource)
        elif resource["name"] not in existing_resources:
            print("Ignoring resource {}".format(resource["name"]))

    # print(yaml.dump(new_user_yaml))
    return yaml.dump(new_user_yaml)
