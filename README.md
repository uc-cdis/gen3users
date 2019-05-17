# gen3users

Utils for Gen3 commons user management.

## user.yaml validation

How to validate a `user.yaml` file:
```
from gen3users.validation import validate_user_yaml

file_name = "my-gen3-commons/user.yaml"
with open(file_name, "r") as f:
    user_yaml = f.read()
    validate_user_yaml(user_yaml, file_name)
```
