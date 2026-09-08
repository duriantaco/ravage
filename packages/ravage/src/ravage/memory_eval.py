from __future__ import annotations

from typing import NoReturn


class MemoryEvalUnavailableError(ValueError):
    """Raised when the retired memory evaluation entry point is called."""


def run_memory_eval(*_args: object, **_kwargs: object) -> NoReturn:
    """
    Fail explicitly until memory A/B evaluation has a supported implementation.

    Retain the entry point so old callers receive an actionable error. In
    particular, never call model clients or write invented benchmark results.
    """
    message = (
        "Memory A/B evaluation is unavailable: active memory is not supported by the "
        "CLI and this entry point has no benchmark evaluator. No evaluation was run "
        "and no report was generated. Use --memory off for supported runs; compare "
        "real, independently recorded results before claiming a memory improvement."
    )
    raise MemoryEvalUnavailableError(message)
