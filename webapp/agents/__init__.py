from .base import AgentProvider
from .claude import provider as claude_provider
from .codex import provider as codex_provider
from .copilot import provider as copilot_provider
from .opencode import provider as opencode_provider

PROVIDERS: dict[str, AgentProvider] = {
    claude_provider.name: claude_provider,
    codex_provider.name: codex_provider,
    copilot_provider.name: copilot_provider,
    opencode_provider.name: opencode_provider,
}

VALID_AGENTS = set(PROVIDERS)
DEFAULT_AGENT = claude_provider.name
PARALLEL_AGENT_VALUE = "all"


def get_provider(agent: str) -> AgentProvider:
    return PROVIDERS.get(agent, claude_provider)
