# policy_engine_adapter.py
"""
Adapter that wraps/normalizes your repository's policy_engine outputs for the firewall.
Ensure this file sits next to your repo's `policy_engine.py` or update imports accordingly.
"""
try:
    import policy_engine
except Exception:
    policy_engine = None

def score_destination(dst_ip: str, ctx: dict):
    """
    Expected to return (score:float 0..1, action:str, reasons:list[str])
    Heuristic mapping:
      - If repo engine exposes `risk_score_for(dst_ip, ctx)` -> map score to actions
      - Else if exposes `classify(dst_ip, ctx)` returning labels -> map labels
      - Else fallback to safe allow
    """
    reasons = []
    if policy_engine is None:
        return 0.0, "allow", ["no-policy-engine"]

    # Try common function names from your repo
    if hasattr(policy_engine, "risk_score_for"):
        score = float(policy_engine.risk_score_for(dst_ip, ctx))
        if score >= 0.9: return score, "drop", ["repo-high-risk"]
        if score >= 0.7: return score, "quarantine", ["repo-medium-risk"]
        if score >= 0.5: return score, "rate_limit", ["repo-elevated"]
        return score, "allow", ["repo-low"]
    if hasattr(policy_engine, "classify"):
        label = policy_engine.classify(dst_ip, ctx)
        reasons.append(f"label:{label}")
        mapping = {"malicious":"drop","suspicious":"quarantine","untrusted":"rate_limit","trusted":"allow"}
        action = mapping.get(str(label).lower(), "allow")
        score = {"malicious":0.95,"suspicious":0.8,"untrusted":0.6,"trusted":0.2}.get(str(label).lower(), 0.2)
        return score, action, reasons

    # Last resort
    return 0.2, "allow", ["repo-default"]
