import click

from .validation import validate_user_yaml


@click.group()
def main():
    """Utils for Gen3 commons user management."""


@main.command()
@click.argument("files", type=str, nargs=-1, required=True)
def validate(files):
    """Validate one or more user.yaml FILES."""

    failed_validation = False
    for file_name in files:
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


if __name__ == "__main__":
    main()
