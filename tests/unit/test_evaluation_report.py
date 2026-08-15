from aegisdesk.evaluation.report import RunReport, ScenarioResult


def _result(
    scenario_id: str,
    *,
    latency_ms: float | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    model_calls: int | None = None,
) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        run_id="run_001",
        task_success=True,
        trajectory_safe=True,
        policy_bypass=False,
        unauthorized_execution=False,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model_calls=model_calls,
    )


def test_all_none_when_nothing_measured() -> None:
    report = RunReport.build([_result("a"), _result("b")])
    assert report.measured_run_count == 0
    assert report.total_latency_ms is None
    assert report.total_input_tokens is None
    assert report.total_output_tokens is None
    assert report.total_model_calls is None


def test_unmeasured_contributes_nothing_not_zero() -> None:
    report = RunReport.build(
        [
            _result("a", latency_ms=10.0, input_tokens=3, output_tokens=5, model_calls=2),
            _result("b"),
        ]
    )
    assert report.measured_run_count == 1
    assert report.total_latency_ms == 10.0
    assert report.total_input_tokens == 3
    assert report.total_output_tokens == 5
    assert report.total_model_calls == 2


def test_measured_aggregates_sum() -> None:
    report = RunReport.build(
        [
            _result("a", latency_ms=10.0, input_tokens=3, output_tokens=5, model_calls=2),
            _result("b", latency_ms=20.0, input_tokens=4, output_tokens=6, model_calls=3),
        ]
    )
    assert report.measured_run_count == 2
    assert report.total_latency_ms == 30.0
    assert report.total_input_tokens == 7
    assert report.total_output_tokens == 11
    assert report.total_model_calls == 5
    # Token and call totals stay integers, not coerced to float by the aggregation.
    assert isinstance(report.total_input_tokens, int)
    assert isinstance(report.total_model_calls, int)


def test_empty_report_aggregates_are_none() -> None:
    report = RunReport.build([])
    assert report.measured_run_count == 0
    assert report.total_latency_ms is None
    assert report.total_model_calls is None
