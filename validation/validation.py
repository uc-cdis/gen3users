import collections
import yaml


def validate_user_yaml(user_yaml):
    try:
        user_yaml_dict = yaml.safe_load(user_yaml)
    except:
        print("Unable to parse YAML file")
        raise
    validate_syntax(user_yaml_dict)
    validate_groups(user_yaml_dict)
    validate_resources(user_yaml_dict)
    validate_roles(user_yaml_dict)
    validate_users(user_yaml_dict)
    print("OK")


# TODO: get(dict, field)
def get_policy_ids(user_yaml_dict):
    return [p["id"] for p in user_yaml_dict["rbac"].get("policies", [])]


def get_group_names(user_yaml_dict):
    return [g["name"] for g in user_yaml_dict["rbac"].get("groups", [])]


def resource_tree_to_paths(user_yaml_dict):
    """
    Builds the list of existing resource paths from the rbac.resources
    section of the user.yaml
    """
    paths_list = []
    for resource in user_yaml_dict["rbac"].get("resources", []):
        resource_tree_to_paths_rec("", paths_list, resource)
    return paths_list


def resource_tree_to_paths_rec(root, paths_list, resource):
    """
    Recursively builds resource paths by appending a slash
    """
    new_root = "{}/{}".format(root, resource["name"])
    if resource["name"] not in ["programs", "projects"]:
        paths_list.append(new_root)
    for sub in resource.get("subresources", []):
        resource_tree_to_paths_rec(new_root, paths_list, sub)


def validate_resource_syntax_recursive(resource):
    """
    Recursively validates the resource tree by checking the syntax
    of subresources
    """
    assert "name" in resource, "Resource without name: {}".format(resource)
    if resource["name"] == "programs" or resource["name"] == "projects":
        assert (
            "subresources" in resource
        ), 'Resource "{}" does not have subresources'.format(resource["name"])
    for subresource in resource.get("subresources", []):
        validate_resource_syntax_recursive(subresource)


def validate_syntax(user_yaml_dict):
    print("- Validating user.yaml syntax")

    # check expected sections are defined
    assert "rbac" in user_yaml_dict, 'Missing "rbac" section'
    assert "users" in user_yaml_dict, 'Missing "users" section'

    # check expected fields are defined
    # - in rbac.groups
    for group in user_yaml_dict["rbac"].get("groups", []):
        assert "name" in group, "Group without name: {}".format(group)
        assert "policies" in group, 'Group "{}" does not have policies'.format(
            group["name"]
        )
        assert "users" in group, 'Group "{}" does not have users'.format(group["name"])
    # - in rbac.policies
    for policy in user_yaml_dict["rbac"].get("policies", []):
        assert "id" in policy, "Policy without id: {}".format(policy)
        assert "role_ids" in policy, 'Policy "{}" does not have role_ids'.format(
            policy["id"]
        )
        assert (
            "resource_paths" in policy
        ), 'Policy "{}" does not have resource_paths'.format(policy["id"])
    # - in rbac.resources
    for resource in user_yaml_dict["rbac"].get("resources", []):
        validate_resource_syntax_recursive(resource)

    # make sure there are no duplicates
    # - in rbac.groups.name
    duplicate_group_names = [
        group_name
        for group_name, count in collections.Counter(
            get_group_names(user_yaml_dict)
        ).items()
        if count > 1
    ]
    assert len(duplicate_group_names) == 0, "Duplicate group names: {}".format(
        duplicate_group_names
    )
    # - in rbac.policies.id
    duplicate_policy_ids = [
        policy_id
        for policy_id, count in collections.Counter(
            get_policy_ids(user_yaml_dict)
        ).items()
        if count > 1
    ]
    assert len(duplicate_policy_ids) == 0, "Duplicate policy ids: {}".format(
        duplicate_policy_ids
    )


def validate_groups(user_yaml_dict):
    print("- Validating groups")
    existing_policies = get_policy_ids(user_yaml_dict)
    for group in user_yaml_dict["rbac"].get("groups", []):
        # check users are defined
        for user_email in group["users"]:
            assert (
                user_email in user_yaml_dict["users"]
            ), 'User "{}" in group "{}" is not defined in main user list'.format(
                user_email, group["name"]
            )
        # check policies are defined
        for policy_id in group["policies"]:
            assert (
                policy_id in existing_policies
            ), 'Policy "{}" in group "{}" is not defined in list of policies'.format(
                policy_id, group["name"]
            )


def validate_resources(user_yaml_dict):
    print("- Validating resources")
    # check resource paths in "rbac.policies" are valid
    # given "rbac.resources" resource tree
    existing_resources = resource_tree_to_paths(user_yaml_dict)
    for policy in user_yaml_dict["rbac"].get("policies", []):
        for resource_path in policy["resource_paths"]:
            assert resource_path.startswith(
                "/"
            ), 'Resource path "{}" should start with a "/"'.format(resource_path)
            assert (
                resource_path in existing_resources
            ), 'Resource "{}" is not defined in resources tree'.format(resource_path)


def validate_roles(user_yaml_dict):
    print("- Validating roles")
    # TODO


def validate_users(user_yaml_dict):
    print("- Validating users")
    for user_email, user_access in user_yaml_dict["users"].items():
        # check policies are defined
        user_policies = user_access.get("policies", [])
        invalid_policies = set(user_policies).difference(get_policy_ids(user_yaml_dict))
        assert (
            len(invalid_policies) == 0
        ), 'Policies {} assigned to user "{}" are not defined in "rbac" section'.format(
            invalid_policies, user_email
        )
