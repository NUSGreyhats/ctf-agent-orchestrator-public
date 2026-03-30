from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


NormalizeLiveEvent = Callable[[dict, dict], dict | None]
NormalizeSavedEvents = Callable[[list[dict]], list[dict]]
BuildCommand = Callable[[dict, str, bool], list[str]]
GetUsageData = Callable[[], dict | None]
GetModels = Callable[[], tuple[tuple[str, str], ...]]

# Type for SDK-based run_agent: yields normalized events
RunAgent = Callable[..., AsyncIterator[dict]]


@dataclass(frozen=True)
class AgentProvider:
    name: str
    label: str
    models: tuple[tuple[str, str], ...]
    default_model: str
    auth_connect_command: str
    autonomous_default: bool
    badge_mode: str
    build_command: BuildCommand
    normalize_saved_events: NormalizeSavedEvents
    normalize_live_event: NormalizeLiveEvent
    get_usage_data: GetUsageData
    get_models: GetModels | None = None
    effort_levels: tuple[tuple[str, str], ...] = ()
    default_effort: str = ""
    # SDK-based agent runner. If set, run_agent_task uses this instead
    # of build_command + subprocess. Signature:
    #   async def run_agent(prompt, model, effort, cwd, continue_session, session_state, **kw) -> AsyncIterator[dict]
    run_agent: RunAgent | None = None

    @property
    def supports_sdk(self) -> bool:
        return self.run_agent is not None

    def resolved_models(self) -> tuple[tuple[str, str], ...]:
        return self.get_models() if self.get_models else self.models

    def resolved_default_model(self) -> str:
        models = self.resolved_models()
        default_model = self.default_model
        model_values = [value for value, _ in models if value]
        if model_values and default_model not in model_values:
            default_model = model_values[0]
        return default_model

    def metadata(self) -> dict:
        models = self.resolved_models()
        default_model = self.resolved_default_model()
        return {
            "name": self.name,
            "label": self.label,
            "models": [
                {"value": value, "label": label}
                for value, label in models
            ],
            "default_model": default_model,
            "auth_connect_command": self.auth_connect_command,
            "autonomous_default": self.autonomous_default,
            "badge_mode": self.badge_mode,
            "effort_levels": [
                {"value": value, "label": label}
                for value, label in self.effort_levels
            ],
            "default_effort": self.default_effort,
        }
