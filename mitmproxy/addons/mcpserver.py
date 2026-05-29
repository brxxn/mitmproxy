from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import fastmcp
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy import http

logger = logging.getLogger(__name__)

_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


class _OriginCheckMiddleware(BaseHTTPMiddleware):
    """Block requests that carry a browser Origin header from a non-localhost host.

    A web page cannot set or spoof the Origin header, so any request arriving
    with Origin pointing at a remote host must have come from a browser tab on
    that site — a classic CSRF vector against local servers.
    """

    async def dispatch(self, request: StarletteRequest, call_next):
        origin = request.headers.get("origin")
        if origin is not None:
            try:
                host = urlparse(origin).hostname or ""
            except Exception:
                host = ""
            if host not in _LOCALHOST_HOSTS:
                return StarletteResponse(
                    "Forbidden: cross-origin browser requests are not allowed",
                    status_code=403,
                )
        return await call_next(request)


_PREVIEW_LEN = 200


def _body_preview(raw: bytes | None) -> str | None:
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1")
    return text[:_PREVIEW_LEN] + ("…" if len(text) > _PREVIEW_LEN else "")


def _flow_summary(flow: Any, body_preview: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": flow.id,
        "type": flow.type,
        "intercepted": flow.intercepted,
        "marked": bool(flow.marked),
        "comment": flow.comment,
        "timestamp_created": flow.timestamp_created,
        "error": str(flow.error.msg) if flow.error else None,
    }
    if isinstance(flow, http.HTTPFlow):
        req = flow.request
        d["request"] = {
            "method": req.method,
            "url": req.pretty_url,
            "http_version": req.http_version,
            "content_length": len(req.raw_content) if req.raw_content is not None else None,
        }
        if body_preview:
            d["request"]["body_preview"] = _body_preview(req.raw_content)
        if flow.response:
            resp = flow.response
            d["response"] = {
                "status_code": resp.status_code,
                "reason": resp.reason,
                "http_version": resp.http_version,
                "content_length": len(resp.raw_content) if resp.raw_content is not None else None,
            }
            if body_preview:
                d["response"]["body_preview"] = _body_preview(resp.raw_content)
    return d


def _flow_detail(flow: Any) -> dict[str, Any]:
    d = _flow_summary(flow)
    if isinstance(flow, http.HTTPFlow):
        d["request"]["headers"] = dict(flow.request.headers)
        if flow.response:
            d["response"]["headers"] = dict(flow.response.headers)
    return d


class MCPServer:

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    def load(self, loader) -> None:
        loader.add_option("mcp_host", str, "localhost", "MCP server host")
        loader.add_option("mcp_port", int, 8082, "MCP server port")

    async def running(self) -> None:
        mcp = fastmcp.FastMCP(
            "mitmproxy",
            instructions="Inspect and control HTTP traffic captured by mitmproxy.",
        )

        @mcp.tool()
        def count_flows(filter_expr: str = "") -> int:
            """Count captured flows matching an optional mitmproxy filter expression. Use this before list_flows to gauge result size and decide whether to tighten the filter."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return 0
            if not filter_expr:
                return len(view)
            flt = flowfilter.parse(filter_expr)
            return sum(1 for flow in view if flt(flow))

        @mcp.tool()
        def list_flows(
            filter_expr: str = "",
            limit: int = 50,
            offset: int = 0,
            body_preview: bool = False,
        ) -> list[dict]:
            """List captured HTTP flows with optional filtering, pagination, and body previews.

            Args:
                filter_expr: mitmproxy filter syntax, e.g. '~u example.com', '~m POST', '~s & ~c 200', '~b keyword'
                limit: maximum number of flows to return (default 50)
                offset: number of matching flows to skip, for pagination
                body_preview: include the first 200 chars of request and response bodies inline
            """
            view = getattr(ctx.master, "view", None)
            if view is None:
                return []
            flt = flowfilter.parse(filter_expr) if filter_expr else None
            results = []
            skipped = 0
            for flow in view:
                if flt is not None and not flt(flow):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                results.append(_flow_summary(flow, body_preview=body_preview))
                if len(results) >= limit:
                    break
            return results

        @mcp.tool()
        def get_flow(flow_id: str) -> dict | None:
            """Get full details including headers for a specific flow by its ID."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return None
            flow = view.get_by_id(flow_id)
            return _flow_detail(flow) if flow else None

        @mcp.tool()
        def get_flow_request_body(flow_id: str) -> str | None:
            """Get the decoded request body for a flow. Returns None if the flow has no body."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return None
            flow = view.get_by_id(flow_id)
            if not isinstance(flow, http.HTTPFlow):
                return None
            try:
                return flow.request.text
            except Exception:
                raw = flow.request.raw_content
                return raw.decode("latin-1") if raw else None

        @mcp.tool()
        def get_flow_response_body(flow_id: str) -> str | None:
            """Get the decoded response body for a flow. Returns None if the flow has no response."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return None
            flow = view.get_by_id(flow_id)
            if not isinstance(flow, http.HTTPFlow) or not flow.response:
                return None
            try:
                return flow.response.text
            except Exception:
                raw = flow.response.raw_content
                return raw.decode("latin-1") if raw else None

        @mcp.tool()
        def resume_flow(flow_id: str) -> bool:
            """Resume an intercepted flow so it continues to its destination. Returns True if the flow was found and resumed."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return False
            flow = view.get_by_id(flow_id)
            if flow is None or not flow.intercepted:
                return False
            flow.resume()
            return True

        @mcp.tool()
        def kill_flow(flow_id: str) -> bool:
            """Kill a live flow, aborting the connection. Returns True if the flow was found."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return False
            flow = view.get_by_id(flow_id)
            if flow is None:
                return False
            flow.kill()
            return True

        @mcp.tool()
        def clear_flows() -> int:
            """Clear all captured flows from the view. Returns the number of flows cleared."""
            view = getattr(ctx.master, "view", None)
            if view is None:
                return 0
            count = len(view)
            view.clear()
            return count

        host = ctx.options.mcp_host
        port = ctx.options.mcp_port
        self._task = asyncio.create_task(
            mcp.run_async(
                transport="sse",
                host=host,
                port=port,
                show_banner=False,
                log_level="warning",
                middleware=[Middleware(_OriginCheckMiddleware)],
            )
        )
        logger.info(f"MCP server listening on http://{host}:{port}/sse")

    async def done(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
