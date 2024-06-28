"""
Module for checking user yaml configurations for security concerns
"""

import yaml
import requests
from os import environ
from sys import exit, stdin, getrecursionlimit
from select import select
from io import StringIO
from cdislogging import get_logger


logging = get_logger("__name__", log_level="info")


def check_yaml(
    resource_names,
    path,
    repo="commons-users",
    owner="uc-cdis",
    verbose=False,
    token=None,
):
    """
    Scans a user.yaml file for occurrences of a given phsid to check if it is open access
    Must store a fine-grain github PAT with read access to the commons-user repository
    `export USER_YAML_GITHUB_PAT=<your-token>`
    Args:
        resource_names (list): A list of resources to check for
        path (str): the relative path from the repository the user.yaml file is hosted on
        repo (str): the repository the user.yaml file is hosted on
        verbose (bool): if true scans entire user.yaml file and finds any instance of specified resources
    """

    content = _retrieve_yaml(path, repo, owner, token)
    anything_found = _check_yaml(resource_names, content, verbose)
    _receive_input(anything_found)
    return


def _retrieve_yaml(path, repo, owner, token):
    if token == None:
        token = environ.get("USER_YAML_GITHUB_PAT")

    response = requests.get(
        "https://api.github.com/repos/{owner}/{repo}/contents/{path}".format(
            owner=owner, repo=repo, path=path
        ),
        headers={
            "accept": "application/vnd.github.raw",
            "authorization": "token {}".format(token),
        },
    )

    if response.status_code == 401 and (token == "" or token == None):
        raise TokenError("Need to set environment variable USER_YAML_GITHUB_PAT")
    content = response.content.decode()
    return content


def _check_yaml(
    resource_names,
    content,
    verbose=False,
):
    raw_content = content
    content = yaml.safe_load(content)

    if type(resource_names) == str:
        resource_names = [resource_names]

    # Figure Out whether authz or rbac
    auth_meth = ""
    try:
        content["rbac"]
        auth_meth = "rbac"
    except KeyError:
        auth_meth = "authz"

    # Store whether any instance of any resource has been found
    anything_found = False

    # Iterate through resource_names
    for phsid in resource_names:
        # Scans for any occurrence of phsid
        if verbose:
            lines = []
            f = StringIO(raw_content)
            logging.info(f"========= Scanning file for {phsid} occurrence =========")
            found = False

            # Find every line number containing the phsid
            for no, line in enumerate(f):
                if phsid in line:
                    lines.append(str(no + 1))
                    found = True
                    anything_found = True

            if found == False:
                logging.info(f"{phsid} not found in file \n")
                # If phsid isn't in the file we can continue to the next phsid
                continue

            # Log locations of phsid
            else:
                lines = ", ".join(lines)
                logging.info(f"{phsid} found in lines {lines} \n")

        logging.info(f"========= Scanning file for {phsid} in open projects =========")
        found = False

        # Track down open data policies (anonymous or all_users)
        policies = content[auth_meth]["policies"]
        open_policies = []

        for i in range(len(policies)):
            # Some user.yaml files don't have these specified so handle with try block
            try:
                bool1 = policies[i]["id"] in content[auth_meth]["anonymous_policies"]
            except KeyError:
                bool1 = False

            try:
                bool2 = policies[i]["id"] in content[auth_meth]["all_users_policies"]
            except KeyError:
                bool2 = False
            # If a policy is in either all_users_policies or anonymous_policies it is open
            if bool1 or bool2:
                open_policies.append(policies[i])

        # Iterate through open policies
        for policy in open_policies:
            for resource_path in policy["resource_paths"]:
                # Check if phsid is hardcoded into the open data reader resource path
                if resource_path[-len(phsid) :] == phsid:
                    logging.info(
                        f"{phsid} found directly in {policy['id']} Resource Path"
                    )
                    found = True
                    anything_found = True

                # Otherwise check under resource path subresources
                else:
                    try:
                        path = content[auth_meth]["user_project_to_resource"][
                            resource_path.strip("/")
                        ]
                        path = path.split("/")
                    except KeyError:
                        path = resource_path.split("/")

                    resources = content[auth_meth]["resources"]

                    subresources = resources

                    # Iterate through path
                    continue_outer = False
                    for j in range(len(path)):
                        for k in range(len(subresources)):
                            if path[j] == subresources[k]["name"]:
                                try:
                                    subresources = subresources[k]["subresources"]
                                    break
                                except KeyError:
                                    # If we run into a keyerror then the resource at the end of the
                                    # current resource_path has no subresources that could hold
                                    # the current phsid. continue to next resource_path
                                    continue_outer = True
                                    break
                    if continue_outer == True:
                        continue

                    locs = []

                    found, locs = _f(subresources, phsid, locs)
                    locs = path + locs
                    locs = "/".join(locs)

                    if found == True:
                        logging.info(f"{phsid} found in open resource under {locs}\n")
                        anything_found = True

        if found == False:
            logging.info(f"{phsid} not found in open projects \n")

    return anything_found


def _receive_input(anything_found):
    # If we find anything ask for input (eventually times out)
    if anything_found:
        print("Would you like to continue? (y/n): ", end="", flush=True)
        timeout = 90
        i = None
        i, o, e = select([stdin], [], [], timeout)

        if i:
            user_response = stdin.readline().strip()
            logging.info(f"User Response: {user_response}")
            if user_response != "y":
                exit(1)
        else:
            logging.info("No user response")
            exit(1)

    # If we reach the end of the function we can return
    return


def _f(subrsrc, phsid, locs):
    for i in range(len(subrsrc)):
        if subrsrc[i]["name"] == phsid:
            return True, locs
        try:
            subrsrc[i]["subresources"]
            locs.append(subrsrc[i]["name"])
            subrsrc, locs = _f(subrsrc[i]["subresources"], phsid, locs)
            if subrsrc == True:
                return subrsrc, locs
        except KeyError:
            pass
    return False, []


class TokenError(Exception):
    pass


if __name__ == "__main__":
    from argparse import ArgumentParser

    args = ArgumentParser()

    args.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all occurrences of phsid in file",
    )

    args.add_argument(
        "-p",
        "--path",
        type=str,
        default="users/ncicrdc/user.yaml",
        help="Relative path from repository home",
    )

    args.add_argument(
        "-r", "--repo", type=str, default="commons-users", help="Repository to search"
    )
    args.add_argument(
        "-o", "--owner", type=str, default="uc-cdis", help="Owner of repository"
    )

    args.add_argument(
        "--phsid",
        type=str,
        nargs="+",
    )

    args = args.parse_args()

    check_yaml(
        resource_names=args.phsid, path=args.path, repo=args.repo, verbose=args.verbose
    )
