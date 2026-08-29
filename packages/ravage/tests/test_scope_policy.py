from __future__ import annotations

import pytest
from pentest_schemas import Scope
from ravage.web_core.scope_policy import (
    assert_authorized_target,
    assert_scoped_same_origin,
    is_local_url,
    remap_local_default_origin,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://127.0.0.2",
        "http://127.1",
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f.0.0.1",
        "http://localhost",
        "http://LOCALHOST",
        "http://0.0.0.0",
        "http://[::]",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
    ],
)
def test_local_url_accepts_loopback_and_unspecified_variants(url: str) -> None:
    assert is_local_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254",
        "http://192.168.1.10",
        "http://198.51.100.10",
        "http://example.com",
        "http://loc\u0430lhost",
        "http://0x100.0.0.1",
        "http://0300.0250.0001.0001",
    ],
)
def test_local_url_rejects_private_metadata_public_and_confusable_hosts(url: str) -> None:
    assert not is_local_url(url)


def test_tools_can_target_secondary_local_origin_when_explicitly_scoped() -> None:
    scope = Scope(
        in_scope=["http://127.0.0.1:8094", "http://127.0.0.1:8095"],
        out_of_scope=[],
    )

    assert_scoped_same_origin(
        "http://127.0.0.1:8094",
        "http://127.0.0.1:8095/console",
        scope=scope,
        allow_remote_target=False,
    )


def test_tools_reject_secondary_local_origin_when_not_scoped() -> None:
    scope = Scope(in_scope=["http://127.0.0.1:8094"], out_of_scope=[])

    with pytest.raises(ValueError, match="must be listed in engagement scope"):
        assert_scoped_same_origin(
            "http://127.0.0.1:8094",
            "http://127.0.0.1:8095/console",
            scope=scope,
            allow_remote_target=False,
        )


def test_remaps_local_default_port_redirect_to_scoped_ephemeral_port() -> None:
    assert (
        remap_local_default_origin(
            "http://localhost:57122",
            "http://localhost/wp-login.php",
        )
        == "http://localhost:57122/wp-login.php"
    )


def test_path_scope_normalizes_parent_segments() -> None:
    scope = Scope(in_scope=["http://127.0.0.1:8094/app"], out_of_scope=[])

    assert_scoped_same_origin(
        "http://127.0.0.1:8094/app",
        "http://127.0.0.1:8094/app/dashboard",
        scope=scope,
        allow_remote_target=False,
    )

    with pytest.raises(ValueError, match="must be listed in engagement scope"):
        assert_scoped_same_origin(
            "http://127.0.0.1:8094/app",
            "http://127.0.0.1:8094/app/../admin",
            scope=scope,
            allow_remote_target=False,
        )


def test_localhost_out_of_scope_is_enforced() -> None:
    scope = Scope(
        in_scope=["http://127.0.0.1:8094"],
        out_of_scope=["http://127.0.0.1:8094/admin"],
    )

    with pytest.raises(ValueError, match="explicitly out of scope"):
        assert_authorized_target(
            "http://127.0.0.1:8094/admin",
            scope=scope,
            allow_remote_target=False,
            agent_name="test",
        )


def test_localhost_missing_scope_error_mentions_local_target() -> None:
    scope = Scope(in_scope=["http://127.0.0.1:8094"], out_of_scope=[])

    with pytest.raises(ValueError, match="local target must be listed in engagement scope"):
        assert_authorized_target(
            "http://127.0.0.1:8095",
            scope=scope,
            allow_remote_target=False,
            agent_name="test",
        )


def test_loopback_variant_is_local_but_still_requires_scope() -> None:
    scope = Scope(in_scope=["http://127.0.0.1:8094"], out_of_scope=[])

    with pytest.raises(ValueError, match="local target must be listed in engagement scope"):
        assert_authorized_target(
            "http://127.0.0.2:8094",
            scope=scope,
            allow_remote_target=False,
            agent_name="test",
        )


def test_loopback_variant_is_allowed_when_explicitly_scoped() -> None:
    scope = Scope(in_scope=["http://127.0.0.2:8094"], out_of_scope=[])

    assert_authorized_target(
        "http://127.0.0.2:8094",
        scope=scope,
        allow_remote_target=False,
        agent_name="test",
    )


def test_metadata_address_is_not_treated_as_localhost() -> None:
    scope = Scope(in_scope=["http://169.254.169.254"], out_of_scope=[])

    with pytest.raises(ValueError, match="only runs against localhost targets"):
        assert_authorized_target(
            "http://169.254.169.254",
            scope=scope,
            allow_remote_target=False,
            agent_name="test",
        )
