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
