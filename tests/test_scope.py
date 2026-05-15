from reconforge.core.scope import ScopeRules, extract_host, is_private_or_special_ip


def test_extract_host_from_url():
    assert extract_host("https://www.example.com/path?q=1") == "www.example.com"


def test_scope_domain_suffix():
    scope = ScopeRules.from_values(["example.com"])
    assert scope.contains("api.example.com")


def test_scope_cidr():
    scope = ScopeRules.from_values(["203.0.113.0/24"])
    assert scope.contains("203.0.113.10")


def test_private_ip_detection():
    assert is_private_or_special_ip("127.0.0.1")

