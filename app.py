import os
import re
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from flask import Flask, jsonify, make_response, request, send_from_directory
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OLM_BASE_URL = "https://olm.vn"
LOGIN_URL = f"{OLM_BASE_URL}/dangnhap"

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
    ),
    "Accept": "application/json, text/html, */*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
}

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_TTL_SECONDS = 60 * 60 * 12


def _cleanup_sessions() -> None:
    now = time.time()
    expired = [sid for sid, data in SESSIONS.items() if now - data.get("last_seen", 0) > SESSION_TTL_SECONDS]
    for sid in expired:
        SESSIONS.pop(sid, None)


def _extract_csrf_token(html: str, cookies_dict: Dict[str, str]) -> str:
    patterns = [
        r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
        r'name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        r'content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, flags=re.IGNORECASE)
        if m and m.group(1).strip():
            return m.group(1).strip()

    xsrf = cookies_dict.get("XSRF-TOKEN") or cookies_dict.get("xsrf-token")
    if xsrf:
        return requests.utils.unquote(xsrf)
    return ""


def _build_session_from_store(store_entry: Dict[str, Any]) -> requests.Session:
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    for k, v in store_entry.get("cookies", {}).items():
        s.cookies.set(k, v, domain="olm.vn")
    csrf = store_entry.get("csrf_token") or ""
    if csrf:
        s.headers["X-CSRF-TOKEN"] = csrf
        s.headers["X-XSRF-TOKEN"] = csrf
    return s


def _is_logged_in_html(html: str, final_url: str = "") -> bool:
    lower = (html or "").lower()
    if "/dangnhap" in (final_url or "").lower():
        return False
    if 'name="password"' in lower and 'name="username"' in lower:
        return False
    if "otp-code-field" in lower:
        return False
    if any(marker in lower for marker in ["dang-xuat", "đăng xuất", "logout", "lớp học của tôi", "hoc-sinh"]):
        return True
    return False


def olm_authenticate(username: str, password: str) -> Dict[str, Any]:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.headers["Referer"] = LOGIN_URL

    get_res = session.get(LOGIN_URL, timeout=15, allow_redirects=True)
    cookies_initial = requests.utils.dict_from_cookiejar(session.cookies)
    csrf_token = _extract_csrf_token(get_res.text, cookies_initial)

    payload: Dict[str, str] = {
        "username": username,
        "password": password,
        "remember": "1",
    }
    if csrf_token:
        payload["_token"] = csrf_token

    post_headers = dict(session.headers)
    if csrf_token:
        post_headers["X-CSRF-TOKEN"] = csrf_token
        post_headers["X-XSRF-TOKEN"] = csrf_token

    post_res = session.post(
        LOGIN_URL,
        data=payload,
        headers=post_headers,
        timeout=15,
        allow_redirects=True,
    )

    cookies_after = requests.utils.dict_from_cookiejar(session.cookies)
    final_csrf = _extract_csrf_token(post_res.text, cookies_after) or csrf_token

    verify_res = session.get(f"{OLM_BASE_URL}/", headers=session.headers, timeout=15, allow_redirects=True)
    cookies_verified = requests.utils.dict_from_cookiejar(session.cookies)
    final_csrf = _extract_csrf_token(verify_res.text, cookies_verified) or final_csrf

    if not _is_logged_in_html(verify_res.text, verify_res.url):
        debug_info = {
            "post_status": post_res.status_code,
            "post_url": str(post_res.url),
            "post_text_head": (post_res.text or "")[:180],
            "verify_url": str(verify_res.url),
            "verify_status": verify_res.status_code,
            "cookies": list(cookies_verified.keys()),
        }
        return {"ok": False, "error": f"Đăng nhập thất bại ({debug_info})"}

    return {
        "ok": True,
        "cookies": cookies_verified,
        "csrf_token": final_csrf,
        "username": username,
    }


def _get_active_session() -> Optional[requests.Session]:
    _cleanup_sessions()
    sid = request.headers.get("X-Session-Id") or request.cookies.get("olm_master_sid")
    if not sid:
        data = request.get_json(silent=True) or {}
        sid = data.get("session_id")
    if not sid or sid not in SESSIONS:
        return None
    SESSIONS[sid]["last_seen"] = time.time()
    return _build_session_from_store(SESSIONS[sid])


@app.route("/")
def index():
    html_path = os.path.join(BASE_DIR, "1008.html")
    if os.path.exists(html_path):
        return send_from_directory(BASE_DIR, "1008.html")
    return jsonify({"status": "ok", "message": "OLM Master backend running"}), 200


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": int(time.time())})


@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or request.form.to_dict() or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu"}), 400

    try:
        auth_result = olm_authenticate(username, password)
    except requests.RequestException as exc:
        return jsonify({"success": False, "message": f"Lỗi kết nối tới OLM: {exc}"}), 502

    if not auth_result.get("ok"):
        return jsonify({"success": False, "message": auth_result.get("error") or "Đăng nhập thất bại"}), 401

    _cleanup_sessions()
    sid = uuid.uuid4().hex
    now = time.time()
    SESSIONS[sid] = {
        "cookies": auth_result["cookies"],
        "csrf_token": auth_result["csrf_token"],
        "username": auth_result["username"],
        "created_at": now,
        "last_seen": now,
    }

    resp = make_response(
        jsonify(
            {
                "success": True,
                "message": "Đăng nhập OLM thành công",
                "session_id": sid,
                "username": username,
            }
        )
    )
    resp.set_cookie("olm_master_sid", sid, httponly=True, samesite="Lax", max_age=SESSION_TTL_SECONDS)
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    body = request.get_json(silent=True) or {}
    sid = request.headers.get("X-Session-Id") or request.cookies.get("olm_master_sid") or body.get("session_id")
    if sid and sid in SESSIONS:
        SESSIONS.pop(sid, None)
    resp = make_response(jsonify({"success": True, "message": "Đã đăng xuất phiên"}))
    resp.delete_cookie("olm_master_sid")
    return resp


@app.route("/api/check-session", methods=["GET", "POST"])
def api_check_session():
    s = _get_active_session()
    if not s:
        return jsonify({"authenticated": False}), 200
    return jsonify({"authenticated": True}), 200


@app.route("/api/assignments", methods=["GET", "POST"])
def api_assignments():
    s = _get_active_session()
    if not s:
        return jsonify({"success": False, "message": "Phiên đăng nhập đã hết hạn hoặc chưa đăng nhập"}), 401

    classes_data: Any = None
    courseware_data: Any = None

    candidate_endpoints = [
        ("classes", f"{OLM_BASE_URL}/api/student/list-classes-of-student"),
        ("classes", f"{OLM_BASE_URL}/list-classes-of-student"),
        ("courseware", f"{OLM_BASE_URL}/api/student/list-courseware-of-student"),
        ("courseware", f"{OLM_BASE_URL}/list-courseware-of-student"),
    ]

    for kind, url in candidate_endpoints:
        try:
            r = s.get(url, timeout=15)
            if r.status_code == 200:
                try:
                    parsed = r.json()
                    if kind == "classes" and classes_data is None:
                        classes_data = parsed
                    elif kind == "courseware" and courseware_data is None:
                        courseware_data = parsed
                except ValueError:
                    continue
        except requests.RequestException:
            continue

    return jsonify(
        {
            "success": True,
            "classes": classes_data,
            "courseware": courseware_data,
        }
    )


@app.route("/api/exam-info", methods=["GET", "POST"])
def api_exam_info():
    s = _get_active_session()
    if not s:
        return jsonify({"success": False, "message": "Chưa đăng nhập phiên OLM"}), 401

    data = request.get_json(silent=True) or request.args.to_dict() or {}
    target_url = (data.get("url") or data.get("link") or "").strip()
    if not target_url:
        return jsonify({"success": False, "message": "Thiếu url/link bài làm"}), 400

    full_url = urljoin(OLM_BASE_URL, target_url)
    try:
        res = s.get(full_url, timeout=15, allow_redirects=True)
        return jsonify(
            {
                "success": True,
                "url": res.url,
                "status_code": res.status_code,
                "html_length": len(res.text),
            }
        )
    except requests.RequestException as exc:
        return jsonify({"success": False, "message": f"Không thể tải thông tin bài: {exc}"}), 502


@app.route("/api/solve", methods=["POST"])
def api_solve():
    s = _get_active_session()
    if not s:
        return jsonify({"success": False, "message": "Chưa đăng nhập phiên OLM"}), 401

    payload = request.get_json(silent=True) or {}
    return jsonify(
        {
            "success": True,
            "message": "Đã nhận yêu cầu /api/solve",
            "received": payload,
        }
    )


@app.route("/api/solve-link", methods=["POST"])
def api_solve_link():
    s = _get_active_session()
    if not s:
        return jsonify({"success": False, "message": "Chưa đăng nhập phiên OLM"}), 401

    payload = request.get_json(silent=True) or {}
    link = (payload.get("link") or payload.get("url") or "").strip()
    if not link:
        return jsonify({"success": False, "message": "Vui lòng cung cấp đường dẫn bài học/bài kiểm tra"}), 400

    return jsonify(
        {
            "success": True,
            "message": "Đã nhận liên kết xử lý",
            "link": urljoin(OLM_BASE_URL, link),
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
