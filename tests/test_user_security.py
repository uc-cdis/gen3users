from gen3users.user_security import _check_yaml


def test_open_access():
    phsids = ["Cornell_GWAS", "Glioma", "Bladder_cancer"]
    assert _check_yaml(phsids, "users/canine/user.yaml") == True


def test_closed_access():
    phsids = ["phs001287", "phs001374"]
    assert _check_yaml(phsids, "users/ncicrdc/user.yaml") == False
