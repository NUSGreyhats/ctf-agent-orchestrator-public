"""Base class for CTF platform plugins."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConfigField:
    """Describes a configuration field for the plugin UI."""

    name: str
    label: str
    field_type: str = "text"  # text, password, url, number, checkbox
    required: bool = True
    placeholder: str = ""
    default: str = ""


@dataclass
class RemoteChallenge:
    """A challenge fetched from a remote platform."""

    remote_id: str
    name: str
    description: str = ""
    category: str = ""
    points: int = 0
    files: list[RemoteFile] = field(default_factory=list)
    solves: int = 0
    solved: bool = False
    tags: list[str] = field(default_factory=list)


@dataclass
class RemoteFile:
    """A file attached to a remote challenge."""

    name: str
    url: str


@dataclass
class SubmitResult:
    """Result of a flag submission."""

    correct: bool
    message: str = ""


class RemoteFileTooLarge(ValueError):
    """Raised when a remote challenge file exceeds the configured limit."""


def format_bytes(num_bytes: int) -> str:
    """Format byte counts for operator-facing messages."""
    value = float(max(0, int(num_bytes)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{int(num_bytes)} B"


async def read_limited_response(resp, max_bytes: int | None = None) -> bytes:
    """Read an httpx streaming response with an optional byte cap."""
    resp.raise_for_status()
    if max_bytes is not None:
        max_bytes = max(0, int(max_bytes))
        content_length = resp.headers.get("content-length")
        if content_length:
            try:
                expected = int(content_length)
            except ValueError:
                expected = None
            if expected is not None and expected > max_bytes:
                raise RemoteFileTooLarge(
                    f"remote file is {format_bytes(expected)}, exceeding "
                    f"remaining limit {format_bytes(max_bytes)}"
                )

    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        if not chunk:
            continue
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise RemoteFileTooLarge(
                f"download exceeded remaining limit {format_bytes(max_bytes)}"
            )
        chunks.append(chunk)
    return b"".join(chunks)


class CTFPlatformPlugin:
    """Base class for CTF platform integrations.

    Subclass this and implement the abstract methods to create a plugin
    that can fetch challenges from a CTF platform.
    """

    name: str = ""
    label: str = ""

    def config_schema(self) -> list[ConfigField]:
        """Return the configuration fields needed to connect.

        The web UI renders these as a form. The user fills them in,
        and the resulting dict is passed to all other methods as `config`.
        """
        raise NotImplementedError

    async def test_connection(self, config: dict) -> str:
        """Test the connection and return a status message.

        Returns a human-readable string like "Logged in as admin"
        or raises an exception on failure.
        """
        raise NotImplementedError

    async def fetch_challenges(
        self, config: dict
    ) -> list[RemoteChallenge]:
        """Fetch all challenges from the platform.

        Returns a list of RemoteChallenge objects. The caller will
        present these to the user for selection before downloading files.
        """
        raise NotImplementedError

    async def download_file(
        self, config: dict, file: RemoteFile, max_bytes: int | None = None
    ) -> bytes:
        """Download a challenge file.

        Handles any authentication needed (cookies, tokens, etc.).
        """
        raise NotImplementedError

    def source_url(self, config: dict) -> str:
        """Return the platform URL for display and connection tracking.

        Default: reads config["url"]. Override for plugins that derive
        the URL from other config fields.
        """
        return config.get("url", "")

    async def start_instance(
        self, config: dict, remote_id: str
    ) -> dict | None:
        """Start a remote instance for a challenge.

        Returns a dict with connection info (e.g. {"host": "...", "port": 1234,
        "type": "web"}) or None if not applicable. Implementations should
        poll until the instance is ready before returning.
        """
        return None

    async def stop_instance(
        self, config: dict, remote_id: str
    ) -> None:
        """Stop a remote instance for a challenge."""
        pass

    async def submit_flag(
        self, config: dict, remote_id: str, flag: str
    ) -> SubmitResult:
        """Submit a flag to the platform.

        Returns a SubmitResult indicating whether the flag was correct.
        """
        raise NotImplementedError
