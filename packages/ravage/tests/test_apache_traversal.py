import pytest
from ravage.probes.apache_traversal import (
    apache_cgi_marker_body,
    apache_cgi_read_body,
    apache_cgi_vectors,
    apache_traversal_vectors,
)

_SHALLOW_DEPTH = 4
_DEEP_DEPTH = 5
_RAW_CGI_POSITION_LIMIT = 10


def test_apache_vectors_are_breadth_before_depth_and_include_late_raw_cgi() -> None:
    vectors = apache_traversal_vectors("Apache/2.4.50 (Unix)")

    first_deep = next(
        index for index, vector in enumerate(vectors) if vector.depth == _DEEP_DEPTH
    )
    assert all(vector.depth == _SHALLOW_DEPTH for vector in vectors[:first_deep])
    assert all(vector.depth == _DEEP_DEPTH for vector in vectors[first_deep:])
    raw_cgi = next(
        index
        for index, vector in enumerate(vectors)
        if vector.family == "raw_percent_chars"
        and vector.mode == "cgi"
        and vector.depth == _SHALLOW_DEPTH
    )
    assert raw_cgi < _RAW_CGI_POSITION_LIMIT
    assert "/.%%32%65/" in vectors[raw_cgi].path_for()


def test_apache_249_prioritizes_single_encoded_families_without_dropping_fallbacks() -> None:
    vectors = apache_traversal_vectors("Apache/2.4.49")

    assert vectors[0].family == "single_encoded_dot"
    assert any(vector.family == "raw_percent_chars" for vector in vectors)


def test_apache_cgi_matrix_reaches_every_family_and_depth_within_lane_budget() -> None:
    vectors = apache_cgi_vectors("Apache/2.4.50")

    assert len(vectors) == 14
    assert all(vector.mode == "cgi" for vector in vectors)
    assert {vector.family for vector in vectors if vector.depth == _DEEP_DEPTH} == {
        vector.family for vector in vectors if vector.depth == _SHALLOW_DEPTH
    }
    first_deep = next(index for index, vector in enumerate(vectors) if vector.depth == _DEEP_DEPTH)
    assert first_deep < 8


def test_apache_cgi_bodies_reject_shell_metacharacters() -> None:
    marker = "RAVAGE_CMD_deadbeef"
    marker_body = apache_cgi_marker_body(marker)
    assert marker not in marker_body
    assert "printf '%s%s'" in marker_body
    assert apache_cgi_read_body("/tmp/flag") == (  # noqa: S108 - simulated remote path.
        "echo; [ -f '/tmp/flag' ] && head -c 8192 -- '/tmp/flag' 2>/dev/null"
    )
    assert "find /" not in marker_body
    assert "cat " not in apache_cgi_read_body("/tmp/flag")  # noqa: S108

    with pytest.raises(ValueError, match="unsafe"):
        apache_cgi_read_body("/tmp/flag;id")  # noqa: S108 - hostile test input.
    with pytest.raises(ValueError, match="unsafe"):
        apache_cgi_read_body("/tmp/flag\nid")  # noqa: S108 - hostile test input.
    with pytest.raises(ValueError, match="unsafe"):
        apache_cgi_marker_body("marker; id")
    with pytest.raises(ValueError, match="unsafe"):
        apache_traversal_vectors("Apache/2.4.50")[0].path_for("/tmp/flag?command=id")
