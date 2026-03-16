"""Tests for core engine utilities and LLM backend URL handling."""

from __future__ import annotations

import requests

from jataayu.core.engine import JataayuEngine, LLMBackend


class DummyResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class TestOpenAICompatEndpoint:
    def test_base_url_with_v1_suffix(self, monkeypatch):
        called = {}

        def fake_post(url, **kwargs):
            called["url"] = url
            return DummyResponse({"choices": [{"message": {"content": "ok"}}]})

        monkeypatch.setattr(requests, "post", fake_post)
        backend = LLMBackend(
            backend="openai",
            base_url="https://api.openai.com/v1",
            api_key="key",
            model="gpt-4o-mini",
        )

        result = backend.call("sys", "user")

        assert result == "ok"
        assert called["url"] == "https://api.openai.com/v1/chat/completions"

    def test_base_url_without_v1_suffix(self, monkeypatch):
        called = {}

        def fake_post(url, **kwargs):
            called["url"] = url
            return DummyResponse({"choices": [{"message": {"content": "ok"}}]})

        monkeypatch.setattr(requests, "post", fake_post)
        backend = LLMBackend(
            backend="openai",
            base_url="https://api.openai.com",
            api_key="key",
            model="gpt-4o-mini",
        )

        result = backend.call("sys", "user")

        assert result == "ok"
        assert called["url"] == "https://api.openai.com/v1/chat/completions"


class TestJsonPayloadExtraction:
    def test_extract_plain_json(self):
        raw = '{"threat_level": "low", "risk_score": 0.3}'
        assert JataayuEngine._extract_json_payload(raw) == raw

    def test_extract_fenced_json(self):
        raw = """```json
{"threat_level": "high", "risk_score": 0.8}
```"""
        assert JataayuEngine._extract_json_payload(raw) == '{"threat_level": "high", "risk_score": 0.8}'

    def test_extract_generic_fence(self):
        raw = """```
{"threat_level": "medium", "risk_score": 0.5}
```"""
        assert JataayuEngine._extract_json_payload(raw) == '{"threat_level": "medium", "risk_score": 0.5}'
