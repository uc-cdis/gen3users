import yaml

from .validation import validate_user_yaml


# turn off array references in the resulting YAML file
yaml.Dumper.ignore_aliases = lambda *args: True


# do not alphabetically sort keys
yaml.add_representer(
    dict,
    lambda self, data: yaml.representer.SafeRepresenter.represent_dict(
        self, data.items()
    ),
)


PRIVILEGE_TO_ROLE_NAME = {
    "create": "creator",
    "read": "reader",
    "update": "updater",
    "delete": "deleter",
    "upload": "uploader",
    "read-storage": "storage_reader",
    "write-storage": "storage_writer",
}


BASIC_ROLES = {
    frozenset(["create"]): PRIVILEGE_TO_ROLE_NAME["create"],
    frozenset(["read"]): PRIVILEGE_TO_ROLE_NAME["read"],
    frozenset(["update"]): PRIVILEGE_TO_ROLE_NAME["update"],
    frozenset(["delete"]): PRIVILEGE_TO_ROLE_NAME["delete"],
    frozenset(["upload"]): PRIVILEGE_TO_ROLE_NAME["upload"],
    frozenset(["read-storage"]): PRIVILEGE_TO_ROLE_NAME["read-storage"],
    frozenset(["write-storage"]): PRIVILEGE_TO_ROLE_NAME["write-storage"],
    frozenset(["read", "read-storage"]): "viewer",
    frozenset(["create", "read", "update", "delete", "read-storage"]): "admin",
    frozenset(["create", "read", "update", "delete"]): "service-admin",
    frozenset(
        [
            "create",
            "read",
            "update",
            "delete",
            "upload",
            "read-storage",
            "write-storage",
        ]
    ): "storage-admin",
    frozenset(
        ["create", "read", "update", "delete", "upload", "read-storage"]
    ): "upload-storage-admin",
    frozenset(
        ["create", "read", "update", "delete", "read-storage", "write-storage"]
    ): "write-storage-admin",
}


def add_basic_roles(user_yaml_dict):
    for permissions, name in BASIC_ROLES.items():
        user_yaml_dict["rbac"]["roles"].append(
            {
                "id": name,
                "permissions": [
                    {
                        "id": PRIVILEGE_TO_ROLE_NAME[p],
                        "action": {"service": "*", "method": p},
                    }
                    for p in permissions
                ],
            }
        )


def auth_id_to_resource_path(user_yaml_dict, auth_id):
    """
    Recursively searches the resource tree for a program or project
    named auth_id.

    Arguments:
        user_yaml_dict {dict} -- Contents of a user.yaml file.
        auth_id {str} -- Program or project name as defined in user access

    Returns:
        [str] -- resource path for this auth_id if it exist, None otherwise
    """
    for resource in user_yaml_dict["rbac"].get("resources", []):
        res = auth_id_to_resource_path_recursive("", resource, auth_id)
        if res:
            return res


def auth_id_to_resource_path_recursive(root, resource, auth_id):
    """
    Recursively searches the resource tree for a program or project
    named auth_id.

    Arguments:
        root {str} -- current resource path
        resource {dict} -- current resource.
        auth_id {str} -- Program or project name as defined in user access

    Returns:
        [str] -- resource path for this auth_id if it exist, None otherwise
    """
    new_root = "{}/{}".format(root, resource["name"])
    if resource["name"] in ["programs", "projects"]:
        for sub in resource.get("subresources", []):
            if sub["name"] == auth_id:
                return "{}/{}".format(new_root, sub["name"])
    for sub in resource.get("subresources", []):
        res = auth_id_to_resource_path_recursive(new_root, sub, auth_id)
        if res:
            return res


def convert_old_user_yaml_to_new_user_yaml(user_yaml, dest_path=None):
    """
    Converts a user.yaml file to the new format required by the
    latest fence and arborist.

    Arguments:
        user_yaml {str} -- Contents of a user.yaml file.

    Keyword Arguments:
        dest_path {str} -- Optional destination file. (default: {None})

    Returns:
        [str] -- Contents of the new user.yaml file.
    """
    # make sure the syntax is valid and expected fields exist
    print("Pre-conversion validation:")
    validate_user_yaml(user_yaml)

    print("Converting...")
    old_user_yaml = yaml.safe_load(user_yaml)
    new_user_yaml = {
        "cloud_providers": old_user_yaml.get("cloud_providers", {}),
        "groups": old_user_yaml.get("groups", {}),
        "users": {},
        "rbac": {
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
                    "id": "uploader",
                    "description": "",
                    "permissions": [
                        {
                            "id": "uploader",
                            "action": {"service": "*", "method": "upload"},
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
                # {
                #     "id": "indexd_record_creator",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_record_creator",
                #             "action": {"service": "indexd", "method": "create"},
                #         }
                #     ],
                # },
                # {
                #     "id": "indexd_record_reader",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_record_reader",
                #             "action": {"service": "indexd", "method": "read"},
                #         }
                #     ],
                # },
                # {
                #     "id": "indexd_record_updater",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_record_updater",
                #             "action": {"service": "indexd", "method": "update"},
                #         }
                #     ],
                # },
                # {
                #     "id": "indexd_delete_record",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_delete_record",
                #             "action": {"service": "indexd", "method": "delete"},
                #         }
                #     ],
                # },
                # {
                #     "id": "indexd_storage_reader",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_storage_reader",
                #             "action": {"service": "indexd", "method": "read_storage"},
                #         }
                #     ],
                # },
                # {
                #     "id": "indexd_storage_writer",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "indexd_storage_writer",
                #             "action": {"service": "indexd", "method": "write_storage"},
                #         }
                #     ],
                # },
                # {
                #     "id": "arborist_creator",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "arborist_creator",
                #             "action": {"service": "arborist", "method": "create"},
                #         }
                #     ],
                # },
                # {
                #     "id": "arborist_reader",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "arborist_reader",
                #             "action": {"service": "arborist", "method": "read"},
                #         }
                #     ],
                # },
                # {
                #     "id": "arborist_updater",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "arborist_updater",
                #             "action": {"service": "arborist", "method": "update"},
                #         }
                #     ],
                # },
                # {
                #     "id": "arborist_deleter",
                #     "description": "",
                #     "permissions": [
                #         {
                #             "id": "arborist_deleter",
                #             "action": {"service": "arborist", "method": "delete"},
                #         }
                #     ],
                # },
            ],
        },
    }

    # add basic roles to RBAC list of roles
    add_basic_roles(new_user_yaml)

    # convert resources
    existing_resources = [
        item.get("name") for item in new_user_yaml["rbac"]["resources"]
    ]
    old_resources = old_user_yaml.get("rbac", {}).get("resources", [])
    for resource in old_resources:
        if resource["name"] == "programs":
            # duplicate programs for backwards compatibility
            new_user_yaml["rbac"]["resources"].append(resource)
            new_user_yaml["rbac"]["resources"].append(
                {"name": "gen3", "subresources": [resource]}
            )
        elif resource["name"] not in existing_resources:
            print("Ignoring resource {}".format(resource["name"]))

    # convert user privileges into roles and policies
    existing_policies = [item.get("id") for item in new_user_yaml["rbac"]["policies"]]
    for user_email, user_access in old_user_yaml.get("users", {}).items():

        # generate user policies
        for project in user_access.get("projects", []):

            # get the resource path.
            # if no resource path is specified, use the auth_id
            if "resource" not in project:
                resource_path = auth_id_to_resource_path(
                    new_user_yaml, project["auth_id"]
                )
                if not resource_path:
                    raise Exception(
                        'auth_id "{}" for user "{}" is not found in list of resources and no resource path has been provided'.format(
                            project["auth_id"], user_email
                        )
                    )
            else:
                resource_path = project["resource"]
            resource_path_parts = resource_path.split("/")

            # convert list of privileges into roles and policies
            privilege = frozenset(project.get("privilege", []))
            try:
                role_names = [BASIC_ROLES[privilege]]
            except KeyError:
                # no existing basic role: create one role for each privilege
                role_names = [PRIVILEGE_TO_ROLE_NAME[p] for p in privilege]

            for role_name in role_names:
                policy_id = "{}_{}".format(".".join(resource_path_parts[1:]), role_name)

                if policy_id not in existing_policies:
                    # add the new policy to RBAC list of policies
                    new_user_yaml["rbac"]["policies"].append(
                        {
                            "id": policy_id,
                            "role_ids": [role_name],
                            "resource_paths": [resource_path],
                        }
                    )
                    existing_policies.append(policy_id)

                # assign the policy to the user
                user_access["policies"].append(policy_id)

        # keep this commented out for now for backwards compatibility
        # if "projects" in user_access:
        #     del user_access["projects"]

        new_user_yaml["users"][user_email] = user_access

    result = yaml.dump(new_user_yaml)

    # make sure the syntax is valid and expected fields exist
    print("Post-conversion validation:")
    validate_user_yaml(result)

    # output result
    if dest_path:
        with open(dest_path, "w") as f:
            print("Saving at {}".format(dest_path))
            yaml.dump(new_user_yaml, f, default_flow_style=False)
    else:
        print(result)

    return result
