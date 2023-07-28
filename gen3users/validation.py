from cdislogging import get_logger
import collections
import logging
import yaml


logger = get_logger("gen3users")
logging.basicConfig()


def assert_and_log(assertion_success, error_message):
    """
    If an assertion fails, logs the provided error message.

    Args:
        assertion_success (bool): result of an assertion.
        error_message (str): message to display if the assertion failed.

    Return:
        assertion_success(bool): result of the assertion.
    """
    if not assertion_success:
        logger.error(error_message)
    return assertion_success


def validate_user_yaml(user_yaml, name="user.yaml"):
    """
    Runs all the validation checks against a user.yaml file.

    Args:
        user_yaml (str): Contents of a user.yaml file.
        name (str): Displayable name of the tested file.
    """
    logger.info("Validating {}".format(name))
    try:
        user_yaml_dict = yaml.safe_load(user_yaml)
        assert user_yaml_dict, "Empty file"
    except Exception:
        logger.error("Unable to parse YAML file")
        raise

    # Remove when rbac field in useryaml properly deprecated
    if "authz" not in user_yaml_dict:
        user_yaml_dict["authz"] = user_yaml_dict.get("rbac", {})

    existing_resources = resource_tree_to_paths(user_yaml_dict)
    ok = validate_syntax(user_yaml_dict)
    ok = validate_groups(user_yaml_dict) and ok
    ok = validate_policies(user_yaml_dict, existing_resources) and ok
    ok = validate_clients(user_yaml_dict) and ok
    ok = validate_user_project_to_resource(user_yaml_dict, existing_resources) and ok
    ok = validate_users(user_yaml_dict, existing_resources) and ok
    ok = validate_roles(user_yaml_dict) and ok
    ok = check_broad_roles(user_yaml_dict) and ok

    if not ok:
        raise AssertionError(
            "user.yaml validation failed. See errors in previous logs."
        )
    else:
        logger.info("OK")


def get_field_from_list(li, field):
    """
    Returns the field value for each dictionary in a list of dictionaries.

    Args:
        li (list[dict]): List of dictionaries.
        field (str): Name of the property to select.

    Return:
        (list)
    """
    return [item.get(field) for item in li]


def resource_tree_to_paths(user_yaml_dict):
    """
    Builds the list of existing resource paths from the authz.resources
    section of the user.yaml.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        paths_list(list[str]): list of existing resource paths.
    """
    paths_list = []

    for resource in user_yaml_dict["authz"].get("resources", []):
        resource_tree_to_paths_recursive("", paths_list, resource)
    return paths_list


def resource_tree_to_paths_recursive(root, paths_list, resource):
    """
    Recursively builds resource paths by appending a slash.

    Args:
        root (str): current resource path.
        paths_list (list[str]): list of existing resource paths.
        resource (dict): current resource.
    """
    new_root = "{}/{}".format(root, resource["name"])
    paths_list.append(new_root)
    for sub in resource.get("subresources", []):
        resource_tree_to_paths_recursive(new_root, paths_list, sub)


def validate_resource_syntax_recursive(resource):
    """
    Recursively validates the resource tree by checking the syntax
    of subresources.

    Args:
        resource (dict): current resource.

    Return:
        ok(bool): whether the validation succeeded.
    """
    ok = True

    ok = (
        assert_and_log("name" in resource, "Resource without name: {}".format(resource))
        and ok
    )

    subresources = resource.get("subresources", [])
    ok = (
        assert_and_log(
            type(subresources) == list,
            'Subresources for resource "{}" should be a list'.format(resource["name"]),
        )
        and ok
    )
    for subresource in subresources:
        ok = validate_resource_syntax_recursive(subresource) and ok

        if resource["name"] == "programs":
            ok = (
                assert_and_log(
                    "-" not in subresource["name"],
                    "{}: Program names cannot contain '-'".format(subresource["name"]),
                )
                and ok
            )

    return ok


def validate_syntax(user_yaml_dict):
    """
    Validates the syntax of the user.yaml by checking expected sections and
    fields are present. Also checks that there are no duplicates in key fields.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """
    logger.info("- Validating user.yaml syntax")
    ok = True

    # check expected sections are defined
    # assert_and_log("authz" in user_yaml_dict, 'Missing "authz" section')
    # TODO: after all user.yamls are migrated to new format, uncomment the assertion and remove these 2 lines (waiting on dcfstaging)
    if not user_yaml_dict.get("authz"):
        user_yaml_dict["authz"] = {}

    if not user_yaml_dict.get("users"):
        user_yaml_dict["users"] = {}

    # check expected fields are defined
    # - in authz.groups
    for group in user_yaml_dict["authz"].get("groups", []):
        ok = (
            assert_and_log("name" in group, "Group without name: {}".format(group))
            and ok
        )
        ok = (
            assert_and_log(
                "policies" in group,
                'Group "{}" does not have policies'.format(group["name"]),
            )
            and ok
        )
        ok = (
            assert_and_log(
                "users" in group, 'Group "{}" does not have users'.format(group["name"])
            )
            and ok
        )
    # - in authz.policies
    for policy in user_yaml_dict["authz"].get("policies", []):
        ok = (
            assert_and_log("id" in policy, "Policy without id: {}".format(policy))
            and ok
        )
        ok = (
            assert_and_log(
                policy.get("role_ids"),
                'Policy "{}" does not have role_ids'.format(policy["id"]),
            )
            and ok
        )
        ok = (
            assert_and_log(
                policy.get("resource_paths"),
                'Policy "{}" does not have resource_paths'.format(policy["id"]),
            )
            and ok
        )
    # - in authz.resources
    for resource in user_yaml_dict["authz"].get("resources", []):
        ok = validate_resource_syntax_recursive(resource) and ok
    # - in users
    for user_email, user_access in user_yaml_dict["users"].items():
        for project in user_access.get("projects", {}):
            ok = (
                assert_and_log(
                    project.get("auth_id"),
                    'Project without auth_id for user "{}": {}'.format(
                        user_email, project
                    ),
                )
                and ok
            )
            ok = (
                assert_and_log(
                    project.get("privilege"),
                    'Project "{}" without privilege section for user "{}"'.format(
                        project["auth_id"], user_email
                    ),
                )
                and ok
            )

    # make sure there are no duplicates
    # - in authz.groups.name
    existing_groups = get_field_from_list(
        user_yaml_dict["authz"].get("groups", []), "name"
    )
    duplicate_group_names = [
        group_name
        for group_name, count in collections.Counter(existing_groups).items()
        if count > 1
    ]
    ok = (
        assert_and_log(
            len(duplicate_group_names) == 0,
            "Duplicate group names: {}".format(duplicate_group_names),
        )
        and ok
    )
    # - in authz.policies.id
    existing_policies = get_field_from_list(
        user_yaml_dict["authz"].get("policies", []), "id"
    )
    duplicate_policy_ids = [
        policy_id
        for policy_id, count in collections.Counter(existing_policies).items()
        if count > 1
    ]
    ok = (
        assert_and_log(
            len(duplicate_policy_ids) == 0,
            "Duplicate policy ids: {}".format(duplicate_policy_ids),
        )
        and ok
    )
    # - in authz.roles.id
    existing_roles = get_field_from_list(user_yaml_dict["authz"].get("roles", []), "id")
    duplicate_role_ids = [
        role_id
        for role_id, count in collections.Counter(existing_roles).items()
        if count > 1
    ]
    ok = (
        assert_and_log(
            len(duplicate_role_ids) == 0,
            "Duplicate role ids: {}".format(duplicate_role_ids),
        )
        and ok
    )

    return ok


def validate_groups(user_yaml_dict):
    """
    Validates the "groups" section of the user.yaml by checking that the users
    and policies used in the groups are defined in the lists of users and in
    the list of policies respectively.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """
    logger.info("- Validating groups")
    ok = True

    existing_policies = get_field_from_list(
        user_yaml_dict["authz"].get("policies", []), "id"
    )
    for group in user_yaml_dict["authz"].get("groups", []):
        # check users are defined
        #### TODO test if users just being in groups is fine with usersync
        for user_email in group["users"]:
            ok = (
                assert_and_log(
                    user_email in user_yaml_dict["users"],
                    'User "{}" in group "{}" is not defined in main user list'.format(
                        user_email, group["name"]
                    ),
                )
                and ok
            )

        # make sure users are not duplicated
        seen = set()
        duplicates = set()
        for user in group["users"]:
            if user not in seen:
                seen.add(user)
            else:
                duplicates.add(user)
        ok = (
            assert_and_log(
                not len(duplicates),
                'Duplicate users in group "{}": {}'.format(
                    group["name"], list(duplicates)
                ),
            )
            and ok
        )

        # check policies are defined
        for policy_id in group["policies"]:
            ok = (
                assert_and_log(
                    policy_id in existing_policies,
                    'Policy "{}" in group "{}" is not defined in list of policies'.format(
                        policy_id, group["name"]
                    ),
                )
                and ok
            )

    for predefined_group in ["anonymous_policies", "all_users_policies"]:
        # check policies are defined
        for policy_id in user_yaml_dict["authz"].get(predefined_group, []):
            ok = (
                assert_and_log(
                    policy_id in existing_policies,
                    'Policy "{}" in group "{}" is not defined in list of policies'.format(
                        policy_id, predefined_group
                    ),
                )
                and ok
            )

    return ok


def validate_policies(user_yaml_dict, existing_resources):
    """
    Validates the "policies" section of the user.yaml by checking that the
    roles and resources used in the policies are defined in the list of roles
    and in the resource tree respectively.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """
    logger.info("- Validating policies")
    ok = True

    existing_roles = get_field_from_list(user_yaml_dict["authz"].get("roles", []), "id")
    for policy in user_yaml_dict["authz"].get("policies", []):
        # check resource paths in "authz.policies" are valid
        # given "authz.resources" resource tree
        for resource_path in policy["resource_paths"]:
            ok = (
                assert_and_log(
                    resource_path.startswith("/"),
                    'Resource path "{}" in policy "{}" should start with a "/"'.format(
                        resource_path, policy["id"]
                    ),
                )
                and ok
            )
            ok = (
                assert_and_log(
                    resource_path in existing_resources,
                    'Resource "{}" in policy "{}" is not defined in resource tree'.format(
                        resource_path, policy["id"]
                    ),
                )
                and ok
            )

        # checks roles are defined
        for role_id in policy["role_ids"]:
            ok = (
                assert_and_log(
                    role_id in existing_roles,
                    'Role "{}" in policy "{}" is not defined in list of roles'.format(
                        role_id, policy["id"]
                    ),
                )
                and ok
            )

    return ok


def validate_clients(user_yaml_dict):
    """
    Validates the "clients" section of the user.yaml by checking that the policies assigned to the client are defined in the lists of policies.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """
    logger.info("- Validating clients")
    ok = True

    existing_policies = get_field_from_list(
        user_yaml_dict["authz"].get("policies", []), "id"
    )
    for client_name, client_details in user_yaml_dict.get("clients", {}).items():
        # check policies are defined
        for policy_id in client_details["policies"]:
            ok = (
                assert_and_log(
                    policy_id in existing_policies,
                    'Policy "{}" for client "{}" is not defined in list of policies'.format(
                        policy_id, client_name
                    ),
                )
                and ok
            )

    return ok


def validate_user_project_to_resource(user_yaml_dict, existing_resources):
    logger.info("- Validating user_project_to_resource mapping")
    ok = True

    for auth_id, resource_path in user_yaml_dict.get(
        "user_project_to_resource", {}
    ).items():
        ok = (
            assert_and_log(
                resource_path in existing_resources,
                'Resource path "{}" for auth_id "{}" is not defined in list of resources'.format(
                    resource_path, auth_id
                ),
            )
            and ok
        )

    return ok


def get_allowed_auth_ids(user_yaml_dict):
    resources = user_yaml_dict["authz"].get("resources", [])
    allowed_auth_ids = set()
    for r in resources:
        if r["name"] == "programs":
            for prog in r.get("subresources", []):
                allowed_auth_ids.add(prog["name"])
                for subr in prog.get("subresources", []):
                    if subr["name"] == "projects":
                        for proj in subr.get("subresources", []):
                            allowed_auth_ids.add(proj["name"])
    return allowed_auth_ids


def validate_users(user_yaml_dict, existing_resources):
    """
    Validates the "users" section of the user.yaml by checking that the
    policies assigned to the users are defined in the list of policies.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """
    logger.info("- Validating users")
    ok = True

    existing_policies = get_field_from_list(
        user_yaml_dict["authz"].get("policies", []), "id"
    )
    allowed_auth_ids = get_allowed_auth_ids(user_yaml_dict)

    for user_email, user_access in user_yaml_dict["users"].items():
        # check policies are defined
        user_policies = user_access.get("policies", [])
        invalid_policies = set(user_policies).difference(existing_policies)
        ok = (
            assert_and_log(
                len(invalid_policies) == 0,
                'Policies {} for user "{}" are not defined in list of policies'.format(
                    invalid_policies, user_email
                ),
            )
            and ok
        )

        # check resource paths in "users.projects.resource" are valid
        # given "authz.resources" resource tree
        for project in user_access.get("projects", {}):
            if "resource" in project:
                ok = (
                    assert_and_log(
                        project["resource"].startswith("/"),
                        'Resource path "{}" in project "{}" for user "{}" should start with a "/"'.format(
                            project["resource"], project["auth_id"], user_email
                        ),
                    )
                    and ok
                )

                ok = (
                    assert_and_log(
                        project["resource"] in existing_resources,
                        'Resource "{}" in project "{}" for user "{}" is not defined in resource tree'.format(
                            project["resource"], project["auth_id"], user_email
                        ),
                    )
                    and ok
                )

            # XXX: (pauline) Code below disabled for now because some commons
            # do not have centralized auth yet, so the auth_id is only used in
            # Fence. We can uncomment and validate manually if needed

            # if no resource path is provided, make sure "auth_id" exists
            # else:
            #     auth_id_ok = project["auth_id"] in allowed_auth_ids or project[
            #         "auth_id"
            #     ] in user_yaml_dict["authz"].get("user_project_to_resource", {})
            #     ok = (
            #         assert_and_log(
            #             auth_id_ok,
            #             'auth_id "{}" for user "{}" is not found in list of resources and no resource path has been provided'.format(
            #                 project["auth_id"], user_email
            #             ),
            #         )
            #         and ok
            #     )

    return ok


def validate_roles(user_yaml_dict):
    """
    Validates the "roles" section of the user.yaml by checking that all
    required fields are present.

    Args:
        user_yaml_dict (dict): Contents of a user.yaml file.

    Return:
        ok(bool): whether the validation succeeded.
    """

    logger.info("- Validating roles")
    ok = True
    roles = user_yaml_dict["authz"].get("roles", [])
    for role in roles:
        role_id = role.get("id")
        permissions = role.get("permissions")
        ok = (
            assert_and_log(role_id, "id not specified in role {}".format(role))
            and assert_and_log(
                permissions,
                "permissions not specified for role {}".format(role_id),
            )
            and ok
        )
        for perm in permissions:
            perm_id = perm.get("id")
            action = perm.get("action")
            ok = (
                assert_and_log(
                    perm_id,
                    "id not specified in permission {} in role {}".format(
                        perm, role_id
                    ),
                )
                and assert_and_log(
                    action,
                    "action not specified in permission {} in role".format(
                        perm_id, role_id
                    ),
                )
                and ok
            )
            service = action.get("service")
            method = action.get("method")
            ok = (
                assert_and_log(
                    service,
                    "service is not specified for action permission {} in role {}".format(
                        perm_id, role_id
                    ),
                )
                and assert_and_log(
                    method,
                    "method is not specified for permission {} in role {}".format(
                        perm_id, role_id
                    ),
                )
                and ok
            )
    return ok


def check_broad_roles(user_yaml_dict):
    """
    Make sure 'service = *' is not used for anonymous or all_users policies. This is dangerous because it
    may allow users to access things in services that were not intended to be accessible. For example:
    - Anonymous users have access to public project "projectA". We use a "reader" role with "service = *".
    - If a user has "read" access for service "requestor" in a project, the Requestor service allows them
    to see access requests for the project.
    - Because of "service = *", anonymous users can see who requested access to "projectA", and whether their
    access was approved!
    """
    ok = True

    all_policies_dict = {
        e["id"]: e for e in user_yaml_dict["authz"].get("policies", [])
    }
    all_roles_dict = {e["id"]: e for e in user_yaml_dict["authz"].get("roles", [])}

    an_policies = user_yaml_dict["authz"].get("anonymous_policies", [])
    al_policies = user_yaml_dict["authz"].get("all_users_policies", [])
    for group_name, policies in [
        ("anonymous_policies", an_policies),
        ("all_users_policies", al_policies),
    ]:
        for policy_name in policies:
            role_names = all_policies_dict[policy_name]["role_ids"]
            for role_name in role_names:
                role = all_roles_dict[role_name]
                for perm in role["permissions"]:
                    msg = f"Permission '{perm['id']}' in role '{role_name}' in policy '{policy_name}' has 'service = *'. This is unsecure because policy '{policy_name}' is granted to public group '{group_name}'. Fix suggestion: restrict this policy to specific methods and services, for example 'read in peregrine' + 'read in guppy' + 'read-storage in fence' for public datasets."
                    ok = assert_and_log(perm["action"]["service"] != "*", msg) and ok

    return ok
