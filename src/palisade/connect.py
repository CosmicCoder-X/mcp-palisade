"""Live introspection of MCP servers.

A deliberate design note: connecting to a stdio server *runs it*. The whole
premise of this tool is that the target may be hostile, so live capture is an
opt-in extra rather than the default path, and every other command is happy to
work from a captured JSON surface that can be reviewed without executing
anything.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from palisade.models import (
    PromptDescriptor,
    ResourceDescriptor,
    ServerSurface,
    ToolDescriptor,
)


class ConnectError(RuntimeError):
    pass


@dataclass
class ServerSpec:
    """How to reach one server."""

    id: str
    transport: str  # stdio | http | sse
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        if self.transport == "stdio":
            return " ".join([self.command, *self.args]).strip()
        return self.url

    @classmethod
    def from_stdio(cls, server_id: str, command_line: str) -> ServerSpec:
        parts = shlex.split(command_line, posix=os.name != "nt")
        if not parts:
            raise ConnectError("empty command line")
        return cls(id=server_id, transport="stdio", command=parts[0], args=parts[1:])

    @classmethod
    def from_url(cls, server_id: str, url: str, transport: str = "http") -> ServerSpec:
        return cls(id=server_id, transport=transport, url=url)


def load_client_config(path: str | Path) -> list[ServerSpec]:
    """Parse a host application's MCP config.

    Handles the ``mcpServers`` / ``servers`` map used by Claude Desktop, Cursor
    and the VS Code MCP config, which is how most people actually enumerate
    what they have installed.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        raise ConnectError(f"{path}: no 'mcpServers' or 'servers' object found")

    specs: list[ServerSpec] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("uri") or ""
        if url:
            transport = entry.get("type") or entry.get("transport") or "http"
            specs.append(
                ServerSpec(
                    id=name,
                    transport="sse" if "sse" in str(transport).lower() else "http",
                    url=url,
                    headers=entry.get("headers") or {},
                )
            )
        elif entry.get("command"):
            specs.append(
                ServerSpec(
                    id=name,
                    transport="stdio",
                    command=entry["command"],
                    args=list(entry.get("args") or []),
                    env=dict(entry.get("env") or {}),
                )
            )
    return specs


def _require_sdk() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise ConnectError(
            "Live capture needs the MCP SDK. Install it with:\n"
            "    pip install 'mcp-palisade[live]'\n"
            "Static analysis of a captured surface works without it."
        ) from exc


async def _collect(session: Any, spec: ServerSpec) -> ServerSurface:
    init = await session.initialize()

    server_info = getattr(init, "serverInfo", None)
    instructions = getattr(init, "instructions", "") or ""

    surface = ServerSurface(
        server_id=spec.id,
        transport=spec.transport,
        origin=spec.origin,
        server_name=getattr(server_info, "name", "") or "",
        server_version=getattr(server_info, "version", "") or "",
        instructions=instructions,
    )

    tools = await session.list_tools()
    for tool in getattr(tools, "tools", []):
        annotations = getattr(tool, "annotations", None)
        surface.tools.append(
            ToolDescriptor(
                name=tool.name,
                description=getattr(tool, "description", "") or "",
                input_schema=getattr(tool, "inputSchema", None) or {},
                annotations=_as_dict(annotations),
            )
        )

    # Prompts and resources are optional capabilities; absence is not an error.
    try:
        prompts = await session.list_prompts()
        for prompt in getattr(prompts, "prompts", []):
            surface.prompts.append(
                PromptDescriptor(
                    name=prompt.name,
                    description=getattr(prompt, "description", "") or "",
                    arguments=[_as_dict(a) for a in getattr(prompt, "arguments", []) or []],
                )
            )
    except Exception:
        pass

    try:
        resources = await session.list_resources()
        for resource in getattr(resources, "resources", []):
            surface.resources.append(
                ResourceDescriptor(
                    uri=str(resource.uri),
                    name=getattr(resource, "name", "") or "",
                    description=getattr(resource, "description", "") or "",
                    mime_type=getattr(resource, "mimeType", "") or "",
                )
            )
    except Exception:
        pass

    return surface


def _as_dict(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    for attr in ("model_dump", "dict"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            try:
                return {k: v for k, v in fn(exclude_none=True).items()}
            except TypeError:
                return dict(fn())
    return {}


async def introspect_async(spec: ServerSpec, timeout: float = 30.0) -> ServerSurface:
    _require_sdk()
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run() -> ServerSurface:
        if spec.transport == "stdio":
            params = StdioServerParameters(
                command=spec.command,
                args=spec.args,
                env={**os.environ, **spec.env} if spec.env else None,
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    return await _collect(session, spec)

        if spec.transport == "sse":
            from mcp.client.sse import sse_client

            async with sse_client(spec.url, headers=spec.headers or None) as (read, write):
                async with ClientSession(read, write) as session:
                    return await _collect(session, spec)

        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(spec.url, headers=spec.headers or None) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                return await _collect(session, spec)

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ConnectError(f"{spec.id}: timed out after {timeout}s") from exc


def introspect(spec: ServerSpec, timeout: float = 30.0) -> ServerSurface:
    """Blocking wrapper around :func:`introspect_async`."""
    return asyncio.run(introspect_async(spec, timeout))
