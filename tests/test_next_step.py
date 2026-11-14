"""What the attacker will likely do next."""
import sys
from pathlib import Path

from app.services import next_step
from app.services.next_step import predict_next_steps

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


def test_predictions_come_after_the_stage_the_attack_has_reached():
    seen = ["T1566", "T1059", "T1204"]          # phishing, then execution
    result = predict_next_steps(seen)

    assert result["mode"] == "next"
    assert result["steps"], "no prediction for a common phishing start"
    reached = next_step.furthest_stage(seen)
    for step in result["steps"]:
        assert next_step.last_stage(step["technique_id"]) > reached
        assert step["technique_id"] not in seen
        assert 0 < step["likelihood"] <= 1


def test_it_never_predicts_what_every_attack_does():
    """'They will use command and control' tells a defender nothing."""
    model = next_step.NextStepModel(list(next_step.attack_profiles().values()))
    predicted = {p["technique_id"] for p in model.rank(["T1566", "T1059"], after_stage=3)}
    assert predicted and not predicted & model.universal


def test_after_a_web_shell_it_expects_credential_theft_or_lateral_movement():
    result = predict_next_steps(["T1190", "T1505", "T1059"])
    predicted = {s["technique_id"] for s in result["steps"]}
    assert predicted & {"T1003", "T1021", "T1078", "T1555", "T1552"}, predicted


def test_a_finished_attack_lists_steps_the_report_does_not_mention():
    result = predict_next_steps(["T1566", "T1059", "T1003", "T1021", "T1486"])
    assert result["mode"] == "unreported"
    assert result["steps"]


def test_no_techniques_no_prediction():
    assert predict_next_steps([])["mode"] == "none"


def test_each_step_says_how_to_stop_it():
    result = predict_next_steps(["T1190", "T1505", "T1059"])
    assert any(s["stop_with"] and s["stop_with"]["id"].startswith("M") for s in result["steps"])


def test_the_evaluation_shows_only_the_first_half_of_an_attack():
    from evaluate_next_step import split_in_half

    techniques = {"T1566", "T1059", "T1003", "T1021", "T1486", "T1041"}
    seen, later, cut = split_in_half(techniques)
    assert seen and later and not seen & later
    assert max(next_step.first_stage(t) for t in seen) == cut
    assert min(next_step.first_stage(t) for t in later) > cut


def test_analysis_includes_the_prediction_and_counts_shared_incidents(clean_memory):
    from app.pipelines.analyze import analyze, ingest

    earlier = ("Attackers exploited a public-facing web server and installed a web shell. "
               "They dumped credentials from LSASS with Mimikatz and moved laterally over RDP "
               "to the file server, then exfiltrated data.")
    ingest(clean_memory, earlier, title="Earlier web shell intrusion", use_llm=False,
           provenance="shared")

    result = analyze(clean_memory, "Attackers exploited a vulnerable public-facing web "
                     "application and uploaded a web shell, then ran PowerShell commands.",
                     use_llm=False, include_simulation=False)
    prediction = result["next_steps"]
    assert prediction["mode"] == "next" and prediction["steps"]
    assert prediction["from_memory"] >= 1


def test_the_downloaded_report_carries_the_prediction():
    from app.services import report

    result = {
        "privacy": {"total_redactions": 0, "verified_clean": True, "counts": {},
                    "sanitized_text": "x"},
        "dna": {"attack_type": "web_exploitation", "initial_vector": "web_exploitation",
                "severity": "high", "signature": "S", "summary": "", "tactics": [],
                "impacts": [], "techniques": [], "cves": [], "cve_details": [],
                "kev": {}, "iocs": {}, "attribution": {}},
        "similar_incidents": [], "mitigations": {},
        "next_steps": predict_next_steps(["T1190", "T1505", "T1059"]), "meta": {},
    }
    text = report.build(result)
    assert "What the attacker will likely do next" in text
