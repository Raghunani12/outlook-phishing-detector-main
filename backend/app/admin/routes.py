import json
from pathlib import Path

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from app.admin.auth import check_password, require_admin
from app.admin import queries

router = APIRouter(prefix="/admin", tags=["admin"])

BASE_DIR = Path(__file__).resolve().parent.parent  # -> app/
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
# Plain Jinja2 (unlike Flask) doesn't ship a `tojson` filter -- needed to
# hand Chart.js data structures to inline <script> blocks safely.
templates.env.filters["tojson"] = lambda v, indent=None: json.dumps(v, default=str, indent=indent)

# Static assets (admin.css) served at /admin/static/*
router.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="admin_static")


@router.get("/login")
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    if check_password(password):
        request.session["admin_authenticated"] = True
        return RedirectResponse(url="/admin", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Incorrect password."})


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/admin/login", status_code=302)


@router.get("")
async def overview(request: Request):
    redirect = require_admin(request)
    if redirect:
        return redirect

    metrics = await queries.get_overview_metrics()
    return templates.TemplateResponse("overview.html", {"request": request, "m": metrics})


@router.get("/users")
async def users_list(request: Request, search: str = ""):
    redirect = require_admin(request)
    if redirect:
        return redirect

    users = await queries.list_users(search=search or None)
    return templates.TemplateResponse("users.html", {"request": request, "users": users, "search": search})


@router.get("/users/{email}")
async def user_detail(request: Request, email: str):
    redirect = require_admin(request)
    if redirect:
        return redirect

    detail = await queries.get_user_detail(email)
    return templates.TemplateResponse("user_detail.html", {"request": request, "d": detail})


@router.get("/scans/{scan_id}")
async def scan_detail(request: Request, scan_id: str):
    redirect = require_admin(request)
    if redirect:
        return redirect

    scan = await queries.get_scan_detail(scan_id)
    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan": scan})


@router.get("/scans/{scan_id}/source")
async def scan_source(request: Request, scan_id: str):
    redirect = require_admin(request)
    if redirect:
        return redirect

    scan = await queries.get_scan_detail(scan_id)
    raw = await queries.get_raw_scan_data(scan_id)
    return templates.TemplateResponse("scan_source.html", {"request": request, "scan": scan, "raw": raw})
