from gen3users.validation import check_broad_roles


def test_check_broad_roles():
    user_yaml_dict = {
        "authz": {
            "policies": [
                {
                    "id": "locked_policy",
                    "role_ids": ["guppy_reader"],
                    "resource_paths": ["/programs/something"],
                },
                {
                    "id": "broad_policy",
                    "role_ids": ["reader"],
                    "resource_paths": ["/programs/something"],
                },
            ],
            "roles": [
                {
                    "id": "guppy_reader",
                    "permissions": [
                        {
                            "id": "guppy_reader",
                            "action": {"service": "guppy", "method": "read"},
                        }
                    ],
                },
                {
                    "id": "reader",
                    "permissions": [
                        {"id": "reader", "action": {"service": "*", "method": "read"}}
                    ],
                },
            ],
        }
    }

    user_yaml_dict["authz"]["anonymous_policies"] = ["locked_policy"]
    ok = check_broad_roles(user_yaml_dict)
    assert ok

    user_yaml_dict["authz"]["anonymous_policies"] = ["broad_policy"]
    ok = check_broad_roles(user_yaml_dict)
    assert not ok

    user_yaml_dict["authz"]["anonymous_policies"] = []
    user_yaml_dict["authz"]["all_users_policies"] = ["locked_policy", "broad_policy"]
    ok = check_broad_roles(user_yaml_dict)
    assert not ok
