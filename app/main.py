import base64
import io
import os
import time
import logging
from urllib.parse import quote

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import storage, vless

logger = logging.getLogger("vless-panel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_DIR = os.path.dirname(__file__)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")
SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
PANEL_TITLE = os.environ.get("PANEL_TITLE", "پنل تانل")

# Choices offered in the settings UI for the global, panel-wide config
# that every generated vless:// link uses from that point on.
FINGERPRINT_CHOICES = ["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"]
ALPN_CHOICES = ["h2,http/1.1", "h2", "http/1.1"]
SECURITY_CHOICES = ["tls", "none"]

# User-Agent substrings belonging to actual VPN client apps. If a request to
# the subscription link comes from one of these, it always gets the raw
# base64 subscription body (never the human-facing info page).
CLIENT_UA_HINTS = (
    "v2ray", "v2rayng", "v2box", "clash", "sing-box", "singbox", "shadowrocket",
    "hiddify", "nekoray", "nekobox", "streisand", "furious", "happ", "karing",
    "loon", "quantumult", "surge", "stash", "matsuri", "husi", "fair vpn",
)

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _not_authed(request: Request):
    if not request.session.get("auth"):
        return RedirectResponse("/login")
    return None


def get_domain(request: Request) -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN") or request.url.hostname


def build_vless_link(request: Request, user_uuid: str, name: str) -> str:
    """
    Build a vless:// share link entirely from the current, panel-wide
    settings (port / security / alpn / fingerprint / ws path / sni).
    Because this is computed fresh on every request rather than frozen at
    user-creation time, changing a setting instantly applies to every
    existing user's link too — not just newly created ones.
    """
    domain = get_domain(request)
    cfg = storage.get_config()
    sni = (cfg.get("sni") or "").strip() or domain

    params = {
        "encryption": "none",
        "security": cfg["security"],
        "type": "ws",
        "host": domain,
        "path": cfg["ws_path"],
    }
    if cfg["security"] == "tls":
        params["sni"] = sni
        params["fp"] = cfg["fingerprint"]
        params["alpn"] = cfg["alpn"]

    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
    return f"vless://{user_uuid}@{domain}:{cfg['port']}?{query}#{quote(name)}"


def build_sub_link(request: Request, user_uuid: str) -> str:
    domain = get_domain(request)
    return f"https://{domain}/sub/{user_uuid}"


def _wants_raw_subscription(request: Request) -> bool:
    """
    Decide whether a request to /sub/{uuid} should get the raw base64
    subscription body (what VPN client apps expect) or the human-friendly
    info page (what someone opening the link in a normal browser wants).
    """
    if request.query_params.get("raw") == "1":
        return True
    ua = request.headers.get("user-agent", "").lower()
    if any(hint in ua for hint in CLIENT_UA_HINTS):
        return True
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return False
    # Ambiguous / no useful Accept header -> assume it's an app, not a browser,
    # so we never accidentally break an existing subscription import.
    return True


def fmt_mb(num_bytes: int) -> float:
    return round((num_bytes or 0) / 1048576, 1)


def enrich_user(request: Request, u: dict) -> dict:
    u = dict(u)
    u["link"] = build_vless_link(request, u["uuid"], u["name"])
    u["sub_link"] = build_sub_link(request, u["uuid"])
    u["status"] = storage.user_status(u)
    u["online"] = storage.is_active_now(u["uuid"])
    u["mb_up"] = fmt_mb(u.get("bytes_up", 0))
    u["mb_down"] = fmt_mb(u.get("bytes_down", 0))
    u["mb_total"] = round(u["mb_up"] + u["mb_down"], 1)
    if u.get("data_limit_mb"):
        u["quota_pct"] = min(100, round(100 * u["mb_total"] / u["data_limit_mb"]))
    else:
        u["quota_pct"] = None
    return u


def nav_ctx(request: Request, active: str) -> dict:
    cfg = storage.get_config()
    return {
        "request": request,
        "active_page": active,
        "panel_title": PANEL_TITLE,
        "domain": get_domain(request),
        "wspath": cfg["ws_path"],
        "config": cfg,
        "online_count": storage.active_connection_count(),
    }


# ---------------------------------------------------------------------------
# health / root
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return PlainTextResponse("ok")


@app.get("/")
async def root(request: Request):
    if request.session.get("auth"):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if request.session.get("auth"):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "panel_title": PANEL_TITLE})


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if storage.verify_admin_password(password, ADMIN_PASSWORD):
        request.session["auth"] = True
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "رمز اشتباهه", "panel_title": PANEL_TITLE},
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# ---------------------------------------------------------------------------
# overview
# ---------------------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    redirect = _not_authed(request)
    if redirect:
        return redirect

    users = [enrich_user(request, u) for u in storage.list_users()]
    total_mb = round(sum(u["mb_total"] for u in users), 1)
    active_count = sum(1 for u in users if u["status"] == "active")
    expired_count = sum(1 for u in users if u["status"] in ("expired", "quota_exceeded"))

    uptime = int(storage.uptime_seconds())
    uptime_str = f"{uptime // 3600} ساعت و {(uptime % 3600) // 60} دقیقه"

    top_users = sorted(users, key=lambda u: u["mb_total"], reverse=True)[:5]

    ctx = nav_ctx(request, "overview")
    ctx.update(
        {
            "total_users": len(users),
            "active_count": active_count,
            "expired_count": expired_count,
            "total_mb": total_mb,
            "total_gb": round(total_mb / 1024, 2),
            "uptime_str": uptime_str,
            "top_users": top_users,
        }
    )
    return templates.TemplateResponse("overview.html", ctx)


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    redirect = _not_authed(request)
    if redirect:
        return redirect

    users = [enrich_user(request, u) for u in storage.list_users()]
    users.sort(key=lambda u: u["created_at"], reverse=True)

    group_filter = request.query_params.get("group") or ""
    if group_filter:
        users = [u for u in users if u.get("group") == group_filter]

    ctx = nav_ctx(request, "users")
    ctx["users"] = users
    ctx["groups"] = storage.list_groups()
    ctx["group_counts"] = storage.group_counts()
    ctx["active_group"] = group_filter
    ctx["total_all_users"] = len(storage.list_users())
    return templates.TemplateResponse("users.html", ctx)


@app.post("/users/add")
async def add_user(
    request: Request,
    name: str = Form(""),
    note: str = Form(""),
    expires_in_days: int = Form(0),
    data_limit_gb: float = Form(0),
    group: str = Form(""),
    new_group: str = Form(""),
):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    data_limit_mb = int(data_limit_gb * 1024) if data_limit_gb else 0
    # if the admin typed a brand-new group name, that wins over the dropdown pick
    final_group = new_group.strip() or group.strip() or storage.DEFAULT_GROUP
    storage.add_user(name.strip() or "user", note.strip(), int(expires_in_days or 0), data_limit_mb, final_group)
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_uuid}/edit")
async def edit_user(
    request: Request,
    user_uuid: str,
    name: str = Form(""),
    note: str = Form(""),
    expires_in_days: int = Form(-1),
    data_limit_gb: float = Form(-1),
    group: str = Form(""),
    new_group: str = Form(""),
):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    data_limit_mb = int(data_limit_gb * 1024) if data_limit_gb >= 0 else None
    final_group = new_group.strip() or group.strip()
    storage.edit_user(
        user_uuid,
        name=name.strip() or None,
        note=note,
        expires_in_days=expires_in_days if expires_in_days >= 0 else None,
        data_limit_mb=data_limit_mb,
        group=final_group or None,
    )
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_uuid}/delete")
async def delete_user(request: Request, user_uuid: str):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.delete_user(user_uuid)
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_uuid}/toggle")
async def toggle_user(request: Request, user_uuid: str):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.toggle_user(user_uuid)
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_uuid}/reset-traffic")
async def reset_traffic(request: Request, user_uuid: str):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.reset_traffic(user_uuid)
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_uuid}/regenerate")
async def regenerate(request: Request, user_uuid: str):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.regenerate_uuid(user_uuid)
    return RedirectResponse("/users", status_code=303)


# ---------------------------------------------------------------------------
# subscription link + QR
# ---------------------------------------------------------------------------
@app.get("/sub/{user_uuid}")
async def subscription(request: Request, user_uuid: str):
    u = storage.get_user(user_uuid)
    if not u:
        return PlainTextResponse("not found", status_code=404)

    if not _wants_raw_subscription(request):
        # A human opened this link in an ordinary browser — show a proper
        # info page (status, quota, copyable config, QR) instead of a raw
        # wall of base64 text that means nothing to them.
        eu = enrich_user(request, u)
        eu["raw_sub_link"] = build_sub_link(request, user_uuid) + "?raw=1"
        return templates.TemplateResponse(
            "sub.html", {"request": request, "panel_title": PANEL_TITLE, "u": eu}
        )

    link = build_vless_link(request, user_uuid, u["name"])
    body = base64.b64encode(link.encode()).decode()

    total = (u.get("data_limit_mb", 0) or 0) * 1024 * 1024
    used_up = u.get("bytes_up", 0)
    used_down = u.get("bytes_down", 0)
    headers = {
        "Subscription-Userinfo": (
            f"upload={used_up}; download={used_down}; total={total}; "
            f"expire={_expire_epoch(u.get('expires_at'))}"
        ),
        "Profile-Title": f"base64:{base64.b64encode(u['name'].encode()).decode()}",
        "Content-Disposition": "inline; filename=subscription.txt",
    }
    return PlainTextResponse(body, headers=headers)


def _expire_epoch(expires_at: str | None) -> int:
    if not expires_at:
        return 0
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(expires_at)
        return int(dt.timestamp())
    except Exception:
        return 0


@app.get("/users/{user_uuid}/qr.png")
async def qr_code(request: Request, user_uuid: str):
    u = storage.get_user(user_uuid)
    if not u:
        return PlainTextResponse("not found", status_code=404)
    link = build_vless_link(request, user_uuid, u["name"])
    try:
        import qrcode
    except ImportError:
        return PlainTextResponse("qrcode package not installed", status_code=500)

    img = qrcode.make(link, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    ctx = nav_ctx(request, "settings")
    ctx["has_custom_password"] = storage.has_custom_password()
    ctx["message"] = request.query_params.get("msg")
    ctx["fingerprint_choices"] = FINGERPRINT_CHOICES
    ctx["alpn_choices"] = ALPN_CHOICES
    ctx["security_choices"] = SECURITY_CHOICES
    ctx["groups"] = storage.list_groups()
    ctx["group_counts"] = storage.group_counts()
    ctx["default_group"] = storage.DEFAULT_GROUP
    return templates.TemplateResponse("settings.html", ctx)


@app.post("/settings/config")
async def update_config(
    request: Request,
    port: int = Form(443),
    security: str = Form("tls"),
    alpn: str = Form("h2,http/1.1"),
    fingerprint: str = Form("chrome"),
    ws_path: str = Form("/tun"),
    sni: str = Form(""),
):
    redirect = _not_authed(request)
    if redirect:
        return redirect

    if security not in SECURITY_CHOICES:
        security = "tls"
    if alpn not in ALPN_CHOICES:
        alpn = "h2,http/1.1"
    if fingerprint not in FINGERPRINT_CHOICES:
        fingerprint = "chrome"
    ws_path = "/" + ws_path.strip().strip("/") if ws_path.strip() else "/tun"
    port = max(1, min(65535, port))

    storage.update_config(
        port=port,
        security=security,
        alpn=alpn,
        fingerprint=fingerprint,
        ws_path=ws_path,
        sni=sni.strip(),
    )
    return RedirectResponse("/settings?msg=تنظیمات+کانفیگ+ذخیره+شد", status_code=303)


@app.post("/settings/groups/add")
async def add_group(request: Request, group_name: str = Form(...)):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.add_group(group_name)
    return RedirectResponse("/settings?msg=گروه+اضافه+شد", status_code=303)


@app.post("/settings/groups/delete")
async def delete_group(request: Request, group_name: str = Form(...)):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.delete_group(group_name)
    return RedirectResponse("/settings?msg=گروه+حذف+شد", status_code=303)


@app.post("/settings/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    redirect = _not_authed(request)
    if redirect:
        return redirect

    if not storage.verify_admin_password(current_password, ADMIN_PASSWORD):
        return RedirectResponse("/settings?msg=رمز+فعلی+اشتباهه", status_code=303)
    if len(new_password) < 6:
        return RedirectResponse("/settings?msg=رمز+جدید+باید+حداقل+۶+کاراکتر+باشه", status_code=303)
    if new_password != confirm_password:
        return RedirectResponse("/settings?msg=تکرار+رمز+مطابقت+نداره", status_code=303)

    storage.set_admin_password(new_password)
    return RedirectResponse("/settings?msg=رمز+با+موفقیت+عوض+شد", status_code=303)


@app.post("/settings/reset-all-traffic")
async def reset_all_traffic(request: Request):
    redirect = _not_authed(request)
    if redirect:
        return redirect
    storage.reset_all_traffic()
    return RedirectResponse("/settings?msg=ترافیک+همه+کاربرا+صفر+شد", status_code=303)


# ---------------------------------------------------------------------------
# VLESS websocket inbound
#
# The path is a single catch-all route rather than a fixed decorator path so
# that changing "مسیر وب‌سوکت" in Settings takes effect immediately, with no
# redeploy required: we just compare the incoming path against whatever is
# currently stored in settings.json before accepting the connection.
# ---------------------------------------------------------------------------
@app.websocket("/{full_path:path}")
async def vless_ws(websocket: WebSocket, full_path: str):
    client_ip = websocket.client.host if websocket.client else "unknown"
    expected_path = storage.get_config()["ws_path"].strip("/")
    if full_path.strip("/") != expected_path:
        logger.warning("WS connect to unknown path '/%s' from %s (expected '/%s')", full_path, client_ip, expected_path)
        await websocket.close(code=1008)
        return

    logger.info("WS connect attempt from %s on /%s", client_ip, full_path)

    await websocket.accept(subprotocol=websocket.headers.get("sec-websocket-protocol"))

    try:
        first = await websocket.receive_bytes()
    except WebSocketDisconnect:
        logger.info("WS disconnected before sending any data (%s)", client_ip)
        return
    except Exception as e:
        logger.warning("WS receive error before header parse: %r", e)
        await websocket.close()
        return

    logger.info("Received %d bytes for handshake from %s", len(first), client_ip)

    try:
        header = vless.parse_vless_header(first)
    except vless.VlessHeaderError as e:
        logger.warning("VLESS header parse failed: %r", e)
        await websocket.close(code=1002)
        return

    logger.info(
        "Parsed VLESS header: uuid=%s dest=%s:%s cmd=%s",
        header["uuid"], header["addr"], header["port"], header["cmd"],
    )

    if not storage.is_user_enabled(header["uuid"]):
        logger.warning("Unknown, disabled, expired or over-quota UUID: %s", header["uuid"])
        await websocket.close(code=1008)
        return

    storage.connection_opened(header["uuid"])

    last_flush = time.monotonic()
    pending = {"up": 0, "down": 0}

    def on_traffic(up: int, down: int):
        nonlocal last_flush
        pending["up"] += up
        pending["down"] += down
        now = time.monotonic()
        if now - last_flush > 5:  # flush to disk at most every 5s
            storage.record_traffic(header["uuid"], pending["up"], pending["down"])
            pending["up"] = 0
            pending["down"] = 0
            last_flush = now

    try:
        await vless.relay(websocket, header, on_traffic)
    except Exception as e:
        logger.warning("Relay ended with error: %r", e)
    finally:
        storage.connection_closed(header["uuid"])
        if pending["up"] or pending["down"]:
            storage.record_traffic(header["uuid"], pending["up"], pending["down"])
        storage.save()
        logger.info("Connection closed for uuid=%s", header["uuid"])
