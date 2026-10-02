"""
OAuth bridge plugin for Remnawave Minishop.

Endpoints:
    POST /api/auth/plugin/start        — start OAuth flow, returns auth_url
    GET  /api/auth/plugin/callback     — receive code from Telegram, issue token
    GET  /api/auth/plugin/subscription — proxy subscription fetch through backend
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Any, Dict
from urllib.parse import urlencode

from aiohttp import ClientTimeout, web

from bot.app.web.context import get_session_factory, get_settings
from bot.app.web.webapp_auth import (
    create_webapp_session_token,
    validate_telegram_oauth_id_token,
)
from bot.app.web.webapp.common import _resolve_telegram_oauth_client_id
from bot.app.web.webapp.auth_referral import _ensure_user_from_telegram
from bot.plugins.spec import Plugin, PluginContext

logger = logging.getLogger(__name__)

PLUGIN_CALLBACK_PATH = "/api/auth/plugin/callback"
PLUGIN_START_PATH = "/api/auth/plugin/start"
PLUGIN_SUBSCRIPTION_PATH = "/api/auth/plugin/subscription"

STATE_TTL_SECONDS = 600


def _urlsafe_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _resolve_callback_url(settings: Any) -> str:
    """Absolute URL of this plugin's callback, reachable by Telegram."""
    base = (
        str(getattr(settings, "MINIAPP_PUBLIC_URL", "") or "")
        or str(getattr(settings, "SUBSCRIPTION_MINI_APP_URL", "") or "")
    ).rstrip("/")
    if not base:
        base = str(getattr(settings, "WEBAPP_BASE_URL", "") or "").rstrip("/")
    if not base:
        raise RuntimeError(
            "Cannot resolve plugin callback base URL: set MINIAPP_PUBLIC_URL"
        )
    return f"{base}{PLUGIN_CALLBACK_PATH}"


class OAuthBridgePlugin(Plugin):
    name = "oauth_bridge"
    version = "0.1.2"
    plugin_api_min_version = 1
    plugin_api_max_version = 1

    def __init__(self) -> None:
        self._pending: Dict[str, dict] = {}

    def setup_web(
        self,
        ctx: PluginContext,
        app: web.Application,
        *,
        scope: str,
    ) -> None:
        if scope != "webapp":
            return
        app.router.add_post(PLUGIN_START_PATH, self._handle_start)
        app.router.add_get(PLUGIN_CALLBACK_PATH, self._handle_callback)
        app.router.add_get(PLUGIN_SUBSCRIPTION_PATH, self._handle_subscription)
        logger.info(
            "[oauth_bridge] registered %s, %s and %s",
            PLUGIN_START_PATH,
            PLUGIN_CALLBACK_PATH,
            PLUGIN_SUBSCRIPTION_PATH,
        )

    # ------------------------------------------------------------------ start
    async def _handle_start(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"ok": False, "error": "invalid_json"}, status=400
            )

        redirect_uri = str(body.get("redirect_uri") or "").strip()
        if not redirect_uri or "://" not in redirect_uri:
            return web.json_response(
                {"ok": False, "error": "invalid_redirect_uri"}, status=400
            )

        client_state = str(body.get("client_state") or "")

        settings = get_settings(request)
        client_id = _resolve_telegram_oauth_client_id(settings)
        client_secret = str(
            getattr(settings, "TELEGRAM_OAUTH_CLIENT_SECRET", "") or ""
        ).strip()
        if not client_id or not client_secret:
            return web.json_response(
                {"ok": False, "error": "telegram_oauth_not_configured"},
                status=503,
            )

        short_state = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)
        code_challenge = _urlsafe_sha256(code_verifier)
        nonce = secrets.token_urlsafe(24)

        self._pending[short_state] = {
            "code_verifier": code_verifier,
            "nonce": nonce,
            "redirect_uri": redirect_uri,
            "client_state": client_state,
            "created_at": time.time(),
        }
        self._cleanup_pending()

        scopes = ["openid", "profile"]
        request_access = str(
            getattr(settings, "TELEGRAM_OAUTH_REQUEST_ACCESS", "") or ""
        )
        for permission in {
            p.strip() for p in request_access.split(",") if p.strip()
        }:
            if permission == "phone":
                scopes.append("phone")
            elif permission == "write":
                scopes.append("telegram:bot_access")

        callback_url = _resolve_callback_url(settings)
        query = urlencode(
            {
                "client_id": str(client_id),
                "redirect_uri": callback_url,
                "response_type": "code",
                "scope": " ".join(scopes),
                "state": short_state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return web.json_response(
            {
                "ok": True,
                "auth_url": f"https://oauth.telegram.org/auth?{query}",
            }
        )

    # --------------------------------------------------------------- callback
    async def _handle_callback(self, request: web.Request) -> web.Response:
        settings = get_settings(request)
        short_state = str(request.query.get("state") or "")

        pending = self._pending.pop(short_state, None)
        if not pending:
            return self._redirect_error("invalid_state", None)

        if time.time() - pending.get("created_at", 0) > STATE_TTL_SECONDS:
            return self._redirect_error(
                "state_expired", pending.get("redirect_uri")
            )

        redirect_uri = pending.get("redirect_uri") or ""
        client_state = pending.get("client_state") or ""

        error = str(request.query.get("error") or "")
        if error:
            return self._redirect_error("cancelled", redirect_uri, client_state)

        code = str(request.query.get("code") or "")
        if not code:
            return self._redirect_error(
                "missing_code", redirect_uri, client_state
            )

        client_id = _resolve_telegram_oauth_client_id(settings)
        client_secret = str(
            getattr(settings, "TELEGRAM_OAUTH_CLIENT_SECRET", "") or ""
        ).strip()
        if not client_id or not client_secret:
            return self._redirect_error(
                "not_configured", redirect_uri, client_state
            )

        token_payload = await self._exchange_code(
            settings,
            code=code,
            code_verifier=pending.get("code_verifier") or "",
        )
        if not token_payload:
            return self._redirect_error(
                "exchange_failed", redirect_uri, client_state
            )

        id_token = str(token_payload.get("id_token") or "")
        telegram_user = await validate_telegram_oauth_id_token(
            id_token,
            settings=settings,
            client_id=int(client_id),
            expected_nonce=pending.get("nonce") or "",
            max_age_seconds=int(
                getattr(settings, "WEBAPP_AUTH_MAX_AGE_SECONDS", 86400) or 86400
            ),
        )
        if not telegram_user:
            return self._redirect_error(
                "invalid_token", redirect_uri, client_state
            )

        session_factory = get_session_factory(request)
        final_user_id: int | None = None
        async with session_factory() as session:
            try:
                db_user = await _ensure_user_from_telegram(
                    session,
                    telegram_user,
                    settings,
                    referral_param=str(telegram_user.get("start_param") or ""),
                )
                if getattr(db_user, "is_banned", False):
                    await session.rollback()
                    return self._redirect_error(
                        "banned", redirect_uri, client_state
                    )
                final_user_id = int(db_user.user_id)
                await session.commit()
            except Exception:
                await session.rollback()
                logger.exception("[oauth_bridge] failed to ensure user")
                return self._redirect_error(
                    "user_failed", redirect_uri, client_state
                )

        if not final_user_id:
            return self._redirect_error("no_user", redirect_uri, client_state)

        token = create_webapp_session_token(settings, final_user_id)

        params = {"token": token}
        if client_state:
            params["state"] = client_state
        sep = "&" if "?" in redirect_uri else "?"
        raise web.HTTPFound(
            location=f"{redirect_uri}{sep}{urlencode(params)}"
        )

    # ------------------------------------------------------------ subscription
    async def _handle_subscription(self, request: web.Request) -> web.Response:
        from bot.app.web.session import extract_authenticated_user_id
        from sqlalchemy import select
        from db.models import User

        settings = get_settings(request)

        user_id = extract_authenticated_user_id(request)
        if not user_id:
            return web.json_response(
                {"ok": False, "error": "unauthorized"}, status=401
            )

        session_factory = get_session_factory(request)
        connect_url: str | None = None
        short_uuid: str | None = None
        async with session_factory() as session:
            try:
                result = await session.execute(
                    select(User).where(User.user_id == user_id)
                )
                db_user = result.scalar_one_or_none()
                if db_user is None:
                    return web.json_response(
                        {"ok": False, "error": "user_not_found"}, status=404
                    )

                for attr in (
                    "panel_subscription_url",
                    "subscription_url",
                    "connect_url",
                    "sub_url",
                ):
                    value = getattr(db_user, attr, None)
                    if value:
                        connect_url = str(value)
                        break

                for attr in (
                    "panel_short_uuid",
                    "short_uuid",
                    "shortUuid",
                ):
                    value = getattr(db_user, attr, None)
                    if value:
                        short_uuid = str(value)
                        break
            except Exception:
                logger.exception(
                    "[oauth_bridge] subscription lookup failed"
                )
                return web.json_response(
                    {"ok": False, "error": "server_error"}, status=500
                )

        settings_base = (
            str(
                getattr(settings, "SUBSCRIPTION_PAGE_URL", "")
                or getattr(settings, "SUBSCRIPTION_URL", "")
                or ""
            ).rstrip("/")
        )
        target_url: str | None = None
        if short_uuid and settings_base:
            target_url = f"{settings_base}/{short_uuid}"
        if not target_url and connect_url:
            target_url = connect_url

        if not target_url:
            return web.json_response(
                {"ok": False, "error": "no_subscription_url"}, status=404
            )

        try:
            from bot.app.web.webapp.telegram_oauth_transport import (
                get_telegram_oauth_http_session,
            )

            http_session = await get_telegram_oauth_http_session(settings)
            async with http_session.get(
                target_url,
                timeout=ClientTimeout(total=20),
                headers={
                    "User-Agent": "v2rayNG/1.8",
                    "Accept": "*/*",
                },
            ) as resp:
                body = await resp.text()
                status = resp.status
                content_type = resp.headers.get(
                    "Content-Type", "application/json"
                )
        except Exception as e:
            logger.exception("[oauth_bridge] subscription fetch failed")
            return web.json_response(
                {"ok": False, "error": "fetch_failed", "detail": str(e)},
                status=502,
            )

        return web.Response(
            body=body,
            status=status,
            content_type=content_type.split(";")[0].strip(),
        )

    # ------------------------------------------------------------------ utils
    async def _exchange_code(
        self,
        settings: Any,
        *,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any] | None:
        client_id = _resolve_telegram_oauth_client_id(settings)
        client_secret = str(
            getattr(settings, "TELEGRAM_OAUTH_CLIENT_SECRET", "") or ""
        ).strip()
        if not client_id or not client_secret or not code or not code_verifier:
            return None

        callback_url = _resolve_callback_url(settings)
        credentials = base64.b64encode(
            f"{client_id}:{client_secret}".encode()
        ).decode("ascii")

        try:
            from bot.app.web.webapp.telegram_oauth_transport import (
                get_telegram_oauth_http_session,
            )

            session = await get_telegram_oauth_http_session(settings)
        except Exception:
            logger.exception(
                "[oauth_bridge] failed to build telegram oauth session"
            )
            return None

        try:
            async with session.post(
                "https://oauth.telegram.org/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": callback_url,
                    "client_id": str(client_id),
                    "code_verifier": code_verifier,
                },
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=ClientTimeout(total=15),
            ) as response:
                payload = await response.json(content_type=None)
                if response.status >= 400:
                    logger.warning(
                        "[oauth_bridge] token exchange failed HTTP %s: %s",
                        response.status,
                        payload,
                    )
                    return None
                return payload if isinstance(payload, dict) else None
        except Exception:
            logger.exception("[oauth_bridge] token exchange exception")
            return None

    def _cleanup_pending(self) -> None:
        now = time.time()
        self._pending = {
            k: v
            for k, v in self._pending.items()
            if now - v.get("created_at", 0) < STATE_TTL_SECONDS
        }

    def _redirect_error(
        self,
        error_code: str,
        redirect_uri: str | None,
        client_state: str = "",
    ) -> web.Response:
        if redirect_uri:
            params = {"error": error_code}
            if client_state:
                params["state"] = client_state
            sep = "&" if "?" in redirect_uri else "?"
            raise web.HTTPFound(
                location=f"{redirect_uri}{sep}{urlencode(params)}"
            )
        return web.json_response(
            {"ok": False, "error": error_code}, status=400
        )


instance = OAuthBridgePlugin()