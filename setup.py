from setuptools import setup
from subprocess import check_output


def get_version():
    try:
        tag = check_output(
            ["git", "describe", "--tags", "--abbrev=0", "--match=[0-9]*"]
        )
        return tag.decode("utf-8").strip("\n")
    except Exception as e:
        raise RuntimeError(
            "The version number cannot be extracted from git tag in this source "
            "distribution; please either download the source from PyPI, or check out "
            "from GitHub and make sure that the git CLI is available."
        ) from e


setup(
    name="gen3users",
    version=get_version(),
    description="Utils for Gen3 commons user management",
    url="https://github.com/uc-cdis/gen3users",
    license="Apache",
    packages=["gen3users"],
    install_requires=["PyYAML~=5.1"],
    entry_points={"console_scripts": ["gen3users=gen3users.main:main"]},
)
