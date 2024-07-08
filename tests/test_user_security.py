from gen3users.user_security import _check_yaml


def test_open_access():
    with open("tests/user.yaml") as f:
        content = f.read()
    assert _check_yaml("phs000218", content) == True


def test_hard_coded():
    with open("tests/user.yaml") as f:
        content = f.read()
    assert _check_yaml("test", content) == True


def test_closed_access():
    with open("tests/user.yaml") as f:
        content = f.read()
    assert _check_yaml("phs001175", content) == False
