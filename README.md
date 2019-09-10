# gen3users

Utils for Gen3 commons user management.

## user.yaml validation

Validate a `user.yaml` file using the CLI:
```
pip install gen3users
gen3users validate first_user.yaml second_user.yaml
```

Validate a `user.yaml` file in a Python script:
```
from gen3users.validation import validate_user_yaml

file_name = "my-gen3-commons/user.yaml"
with open(file_name, "r") as f:
    user_yaml = f.read()
    validate_user_yaml(user_yaml, file_name)
```

## user.yaml conversion

Converts a `user.yaml` file from the old format to the new ABAC-based centralized auth format, required by the latest Fence and Arborist.

Convert a `user.yaml` file using the CLI:
```
pip install gen3users
gen3users convert old_user.yaml [new_user.yaml]
```

Convert a `user.yaml` in a Python script:
```
from gen3users.conversion import convert_old_user_yaml_to_new_user_yaml

src_file_name = "my-gen3-commons/old_user.yaml"
dst_file_name = "my-gen3-commons/new_user.yaml"
with open (src_file_name, "r") as f:
        user_yaml = f.read()
        convert_old_user_yaml_to_new_user_yaml(user_yaml, dst_file_name)

```
