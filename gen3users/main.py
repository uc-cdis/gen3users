import argparse
import os

from gen3users.validation import validate_user_yaml


def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Utils for Gen3 commons user management"
    )
    subs = parser.add_subparsers(dest="command")
    validate = subs.add_parser("validate", help="Validate one or more user.yaml files")
    validate.add_argument(
        "file_names",
        type=str,
        nargs=argparse.ONE_OR_MORE,
        help="One or more user.yaml files",
    )

    args = parser.parse_args()
    return args


def main(args=None):
    if args is None:
        args = get_command_line_args()

    # validate user.yaml files
    if args.command == "validate":
        failed_validation = False
        for file_name in getattr(args, "file_names", []):
            try:
                with open(file_name, "r") as f:
                    user_yaml = f.read()
                    validate_user_yaml(user_yaml, file_name)
            except Exception as e:
                print(e)
                failed_validation = True
            print("")
        if failed_validation:
            raise Exception("user.yaml validation failed. See errors in previous logs.")

    else:
        raise Exception("Unknown subcommand {}".format(args.command))


if __name__ == "__main__":
    main()
