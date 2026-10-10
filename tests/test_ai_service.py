import json

import pytest

from analyzers import ai_service


def test_cosine_search_ranks_semantically_nearest_vectors():
    matches = ai_service.rank_vectors([1.0, 0.0], [
        {"id": 1, "kind": "error", "title": "near", "vector": json.dumps([0.9, 0.1])},
        {"id": 2, "kind": "error", "title": "far", "vector": json.dumps([0.0, 1.0])},
    ], threshold=0.2)

    assert [match["id"] for match in matches] == [1]
    assert matches[0]["similarity"] > 0.9


def test_error_clustering_groups_neighbors_without_joining_unrelated_vectors():
    clusters = ai_service.cluster_vectors([
        {"id": 1, "title": "A", "vector": json.dumps([1.0, 0.0])},
        {"id": 2, "title": "A variant", "vector": json.dumps([0.99, 0.01])},
        {"id": 3, "title": "B", "vector": json.dumps([0.0, 1.0])},
    ], threshold=0.9)

    assert len(clusters) == 1
    assert clusters[0]["count"] == 2


def test_redaction_removes_credentials_and_email_addresses():
    clean = ai_service.redact_text("api_key=abcd1234 and owner@example.com")

    assert "abcd1234" not in clean
    assert "owner@example.com" not in clean
    assert "REDACTED" in clean


def test_embedding_payload_uses_local_configured_model(monkeypatch):
    monkeypatch.setattr(ai_service.config, "AI_ENABLED", True)
    monkeypatch.setattr(ai_service.config, "OLLAMA_EMBED_MODEL", "test-embed")
    calls = []

    def fake_request(method, path, payload, timeout=None):
        calls.append((method, path, payload))
        return {"embeddings": [[0.25, 0.75]]}

    monkeypatch.setattr(ai_service, "_request", fake_request)

    assert ai_service.embed_texts(["test error"]) == [[0.25, 0.75]]
    assert calls[0][0:2] == ("POST", "/api/embed")
    assert calls[0][2]["model"] == "test-embed"


def test_embedding_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(ai_service.config, "AI_ENABLED", False)

    with pytest.raises(ai_service.AIUnavailable, match="disabled"):
        ai_service.embed_text("test error")


def test_explanation_requires_schema_and_labels_suggestions(monkeypatch):
    monkeypatch.setattr(ai_service.config, "AI_ENABLED", True)
    captured = {}
    explanation = {
        "explanation": "The divisor may be zero.",
        "verified_facts": ["A division-by-zero error was reported."],
        "possible_causes": ["The input list may be empty."],
        "suggested_checks": ["Check the divisor before dividing."],
        "disclaimer": "Suggestions are not guarantees.",
    }

    def fake_request(method, path, payload, timeout=None):
        captured.update(payload)
        return {"message": {"content": json.dumps(explanation)}}

    monkeypatch.setattr(ai_service, "_request", fake_request)
    result = ai_service.explain_analysis({
        "kind": "error", "title": "ZeroDivisionError", "summary": "divide by zero",
        "result": {"error_type": "ZeroDivisionError", "message": "division by zero",
                   "explanation": "The divisor was zero."},
    })

    assert result == explanation
    assert captured["format"] == "json"
    assert "untrusted data" in captured["messages"][0]["content"]