import os
from dotenv import load_dotenv

load_dotenv()

_client = None
_client_failed = False


def _get_client():
    """
    Create the Supabase client lazily. A missing or invalid Supabase config
    must never stop the API from starting; storage is optional.
    """
    global _client, _client_failed
    if _client is not None or _client_failed:
        return _client

    url, key = os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    if not url or not key:
        print("Supabase not configured; storage disabled.")
        _client_failed = True
        return None

    try:
        from supabase import create_client
        _client = create_client(url, key)
    except Exception as e:
        print("Supabase disabled:", e)
        _client_failed = True
    return _client


def _insert(table: str, row: dict) -> bool:
    client = _get_client()
    if client is None:
        return False
    try:
        client.table(table).insert(row).execute()
        return True
    except Exception as e:
        print("Supabase error:", e)
        return False


def save_feedback(is_false_positive: bool, risk_level: str, comment: str = "") -> bool:
    return _insert("feedback", {
        "is_false_positive": is_false_positive,
        "risk_level": risk_level,
        "comment": comment,
    })


def save_analysis(channel: str, language: str, risk_score: int,
                  risk_level: str, classification: str,
                  signal_types: list) -> bool:
    return _insert("analysis_log", {
        "channel": channel,
        "language": language,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "signal_types": signal_types,
    })
