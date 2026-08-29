from pentest_schemas import Scope
from ravage.runtime import ScopeFirewall
from ravage.runtime.iptables import generate_iptables_commands


def test_generate_iptables_commands_includes_scope_rules() -> None:
    rules = generate_iptables_commands(
        Scope(
            in_scope=["http://192.0.2.10:80", "10.10.10.0/24"],
            out_of_scope=["198.51.100.10"],
        )
    )

    assert "iptables -P OUTPUT DROP" in rules
    assert "--dport 53" not in rules
    assert "iptables -A OUTPUT -d 198.51.100.10 -j DROP" in rules
    assert "iptables -A OUTPUT -p tcp -d 192.0.2.10 --dport 80 -j ACCEPT" in rules
    assert "iptables -A OUTPUT -d 10.10.10.0/24 -j ACCEPT" in rules


def test_generate_iptables_commands_skips_hostnames() -> None:
    rules = generate_iptables_commands(
        Scope(in_scope=["http://target:80"], out_of_scope=["example.com"])
    )

    assert "iptables -A OUTPUT -d target" not in rules
    assert "iptables -A OUTPUT -d example.com" not in rules
    assert "# skipped hostname in_scope entry" in rules
    assert "# skipped hostname out_of_scope entry" in rules


def test_out_of_scope_rule_precedes_overlapping_in_scope_rule() -> None:
    destination = "198.51.100.10"
    rules = generate_iptables_commands(
        Scope(
            in_scope=[f"http://{destination}:80"],
            out_of_scope=[f"http://{destination}:80"],
        )
    ).splitlines()

    drop_rule = f"iptables -A OUTPUT -d {destination} -j DROP"
    accept_rule = f"iptables -A OUTPUT -p tcp -d {destination} --dport 80 -j ACCEPT"
    assert rules.index(drop_rule) < rules.index(accept_rule)


def test_scope_firewall_exclusion_overrides_overlapping_in_scope_entry() -> None:
    firewall = ScopeFirewall(
        in_scope=("https://example.test/app",),
        out_of_scope=("https://example.test/app/admin",),
    )

    assert firewall.allows("https://example.test/app/profile")
    assert not firewall.allows("https://example.test/app/admin")
    assert not firewall.allows("https://example.test/app/admin/users")


def test_scope_firewall_rejects_lookalike_prefix_origin() -> None:
    firewall = ScopeFirewall(in_scope=("https://example.test/app",))

    assert not firewall.allows("https://example.test.evil/app")
    assert not firewall.allows("https://example.test:444/app")
    assert not firewall.allows("https://example.test/application")


def test_scope_firewall_uses_canonical_iptables_renderer() -> None:
    scope = Scope(
        in_scope=["http://192.0.2.10:80"],
        out_of_scope=["http://198.51.100.10:80"],
    )

    assert ScopeFirewall.from_scope(scope).script_lines == tuple(
        generate_iptables_commands(scope).splitlines()
    )
