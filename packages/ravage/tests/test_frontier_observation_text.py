from __future__ import annotations

import json

from ravage.agent_core.frontier_observation_text import output_observation_texts


def test_nested_result_ignores_source_and_keeps_stdout() -> None:
    observation = json.dumps(
        {
            "result": {
                "command": ["python3", "print('EXTRACTED_PASSWORD=', source)"],
                "stdout": "EXTRACTED_PASSWORD=target-output",
            }
        }
    )

    assert output_observation_texts(observation) == ("EXTRACTED_PASSWORD=target-output",)


def test_structured_source_without_output_has_no_trusted_text() -> None:
    observation = json.dumps({"code": "print('CAL T same')\nprint('CAL F same')"})

    assert output_observation_texts(observation) == ()
