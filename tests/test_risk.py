from pad.risk.score import risk_score

def test_risk_score():
    assert risk_score(3.0, 1.0, 2.0) == 6.0
