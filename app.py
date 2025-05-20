import os, json, zipfile, threading, requests, re, smtplib, traceback, hashlib
from datetime import datetime, date, time as t, timedelta, timezone
from io import BytesIO
from email.message import EmailMessage
from urllib.parse import unquote_plus

import streamlit as st
from streamlit.runtime.scriptrunner import add_script_run_ctx

# ─────────── constants ───────────
DEFAULT_TOKEN = "975449712b54d5463a9bc22eddfacb006D57EA7D1C7F73A4690338D42F14313ED12D0C1F"
# now matches exactly 8‐digit dates and ensures no extra chars
DATE_RE  = re.compile(r"(20\d{6})(?=\D|$)")
EU_BG    = timezone(timedelta(hours=2))         # Europe/Belgrade
SETFILE  = "smtp_settings.json"
TIMERKEY = "auto_timer"

# ─────────── helpers ────────────
def normalize_base_url(u: str) -> str:
    u = u.rstrip("/")
    return u + "/wialon/ajax.html" if not u.endswith("/wialon/ajax.html") else u

def sha(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

def load_settings() -> dict:
    if os.path.exists(SETFILE):
        try:
            return json.load(open(SETFILE, encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_settings(s: dict) -> None:
    json.dump(s, open(SETFILE, "w", encoding="utf-8"))

def wialon_call(svc: str, sid: str, params: dict | None, base: str, *, get=False):
    payload = {"svc": svc, "sid": sid}
    if params is not None:
        payload["params"] = json.dumps(params, separators=(",", ":"))
    req = requests.get if get else requests.post
    r = req(base,
            params=payload if get else None,
            data=payload if not get else None,
            timeout=20)
    return r.json()

# ─────────── Wialon API ───────────
def login_token(token: str, base: str) -> str | None:
    try:
        r = requests.get(base,
                         params={"svc": "token/login",
                                 "params": json.dumps({"token": token})},
                         timeout=20).json()
        if "error" in r:
            raise RuntimeError(f"Wialon login error: {r}")
        return r["eid"]
    except Exception as e:
        st.error(e)
        return None

def get_units(sid: str, base: str):
    res = wialon_call("core/search_items", sid,
        {"spec": {"itemsType": "avl_unit", "propName": "sys_name",
                  "propValueMask": "*", "sortType": "sys_name"},
         "force": 1, "flags": 1, "from": 0, "to": 0}, base)
    if isinstance(res, dict) and res.get("error"):
        # if error 5, attempt re-login
        if res["error"] == 5:
            settings = st.session_state["settings"]
            new_sid = login_token(settings.get("token", DEFAULT_TOKEN), settings["base_url"])
            if new_sid:
                settings["sid"] = new_sid
                save_settings(settings)
                res = wialon_call("core/search_items", new_sid,
                    {"spec": {"itemsType": "avl_unit", "propName": "sys_name",
                              "propValueMask": "*", "sortType": "sys_name"},
                     "force": 1, "flags": 1, "from": 0, "to": 0}, base)
            else:
                raise RuntimeError("Access denied (error 5) and re-login failed.")
        else:
            raise RuntimeError(res)
    return [{"id": it["id"],
             "name": it.get("nm", "N/A"),
             "reg": it.get("prp", {}).get("reg_number", "")}
            for it in res.get("items", [])]

def list_files(sid: str, uid: int, day: date, base: str):
    res = wialon_call("file/list", sid,
        {"itemId": uid, "storageType": 2, "path": "tachograph/",
         "mask": "*", "recursive": False, "fullPath": False}, base)
    if isinstance(res, dict) and res.get("error"):
        # retry on error 5
        if res["error"] == 5:
            settings = st.session_state["settings"]
            new_sid = login_token(settings.get("token", DEFAULT_TOKEN), settings["base_url"])
            if new_sid:
                settings["sid"] = new_sid
                save_settings(settings)
                res = wialon_call("file/list", new_sid,
                    {"itemId": uid, "storageType": 2, "path": "tachograph/",
                     "mask": "*", "recursive": False, "fullPath": False}, base)
            else:
                raise RuntimeError("Access denied (error 5) and re-login failed.")
        else:
            raise RuntimeError(res)

    out = []
    for f in res:
        # by create/modify date
        for key in ("ct", "mt"):
            if key in f and datetime.fromtimestamp(f[key], tz=timezone.utc).date() == day:
                out.append(f)
                break
        else:
            m = DATE_RE.search(f["n"])
            if m:
                file_date = datetime.strptime(m.group(1), "%Y%m%d").date()
                if file_date == day:
                    out.append(f)
    out.sort(key=lambda x: x.get("mt", x.get("ct", 0)), reverse=True)
    return out

def get_file(sid: str, uid: int, fname: str, base: str) -> bytes | None:
    r = requests.get(base,
        params={"svc": "file/get", "sid": sid,
                "params": json.dumps({"itemId": uid, "storageType": 2,
                                      "path": f"tachograph/{fname}"})}, timeout=20)
    return r.content if r.status_code == 200 else None

# ─────────── SMTP & scheduler ───────────
def send_mail(subj: str, body: str, att: bytes | None,
              fname: str, s: dict):
    try:
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subj, s["username"], s["recipients"]
        msg.set_content(body)
        if att:
            msg.add_attachment(att, maintype="application", subtype="zip", filename=fname)
        with smtplib.SMTP(s["server"], int(s["port"])) as smtp:
            smtp.starttls()
            smtp.login(s["username"], s["password"])
            smtp.send_message(msg)
    except Exception as e:
        st.error(f"SMTP error: {e}")

def schedule_nightly(base: str):
    tmr = st.session_state.get(TIMERKEY)
    if tmr and tmr.is_alive():
        tmr.cancel()

    s = st.session_state["settings"]
    if not s.get("auto_send"):
        return

    now = datetime.now(EU_BG)
    run_dt = datetime.combine(
        now.date() + (timedelta(days=1) if now.time() >= t(2, 5) else timedelta()),
        t(2, 5), tzinfo=EU_BG)
    delay = (run_dt - now).total_seconds()

    def job():
        try:
            sid, baseu = s.get("sid"), s["base_url"]
            if not sid:
                return
            units = get_units(sid, baseu)
            prev = (datetime.now(EU_BG) - timedelta(days=1)).date()
            buf = BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for u in units:
                    for f in list_files(sid, u["id"], prev, baseu):
                        data = get_file(sid, u["id"], f["n"], baseu)
                        if data:
                            z.writestr(os.path.join(u["reg"] or u["name"], f["n"]), data)
            buf.seek(0)
            send_mail(f"DDD fajlovi za {prev.strftime('%d.%m.%Y')}",
                      "Automatski ZIP sa svim jučerašnjim fajlovima.",
                      buf.read(), f"DDD_{prev}.zip", s)
        except Exception:
            traceback.print_exc()
        finally:
            schedule_nightly(base)

    tmr = threading.Timer(delay, job)
    tmr.daemon = True
    add_script_run_ctx(tmr)
    tmr.start()
    st.session_state[TIMERKEY] = tmr

# ─────────── UI ───────────
def main():
    st.set_page_config("Wialon DDD Manager", layout="wide")

    qs = st.query_params()
    base_url = normalize_base_url(unquote_plus(qs.get("baseUrl", ["https://hst-api.wialon.com"])[0]))
    sid_qs   = qs.get("sid", [None])[0]

    if "settings" not in st.session_state:
        st.session_state["settings"] = load_settings()
    s = st.session_state["settings"]
    s.setdefault("base_url", base_url)
    if sid_qs:
        s["sid"] = sid_qs

    page = st.sidebar.radio("Navigacija", ["Files", "Admin"])

    if page == "Admin":
        # ... (admin panel unchanged) ...
        st.header("Admin panel")
        # [admin code here, saving settings calls schedule_nightly]
        # omitted for brevity
        # ensure save_settings(s); schedule_nightly(s["base_url"]) on save
    else:
        if not s.get("sid"):
            if st.button("Login tokenom"):
                sid = login_token(s.get("token", DEFAULT_TOKEN), s["base_url"])
                if sid:
                    s["sid"] = sid
                    save_settings(s)
                    schedule_nightly(s["base_url"])
                    st.experimental_rerun()
            st.info("Dodaj ?sid=... u URL ili se prijavi tokenom.")
            st.stop()

        units = get_units(s["sid"], s["base_url"])
        col_left, col_right = st.columns([1, 2])

        with col_left:
            st.markdown("### Vozila")
            day = st.date_input("Datum", date.today(), key="datum")
            q   = st.text_input("Pretraga", key="pretraga")
            filtered = [u for u in units if q.lower() in (u["reg"] + u["name"]).lower()]
            if not filtered:
                st.warning("Nema vozila."); st.stop()
            sel_label = st.radio("Lista vozila",
                                 [f"{u['reg']} — {u['name']}" for u in filtered])
            unit = next(u for u in filtered if f"{u['reg']} — {u['name']}" == sel_label)

        with col_right:
            st.markdown(f"### Fajlovi za **{unit['reg']}**")
            files = list_files(s["sid"], unit["id"], day, s["base_url"])
            if not files:
                st.info("Nema fajlova."); st.stop()

            checked = []
            for f in files:
                if st.checkbox(f["n"], key=f"{unit['id']}_{f['n']}"):
                    checked.append(f["n"])

            st.write("---")
            if not checked:
                st.info("Izaberi fajlove.")
                st.stop()

            c1, c2 = st.columns(2)
            with c1:
                if len(checked) == 1:
                    data = get_file(s["sid"], unit["id"], checked[0], s["base_url"])
                    if data:
                        st.download_button("Preuzmi fajl", data, checked[0],
                                           mime="application/octet-stream")
                else:
                    buf = BytesIO()
                    with zipfile.ZipFile(buf, "w") as z:
                        for fn in checked:
                            d = get_file(s["sid"], unit["id"], fn, s["base_url"])
                            if d: z.writestr(fn, d)
                    buf.seek(0)
                    st.download_button("Preuzmi ZIP", buf.read(),
                                       f"{unit['reg']}_{day}.zip",
                                       mime="application/zip")
            with c2:
                if st.button("Pošalji e-mail"):
                    if len(checked) == 1:
                        att = get_file(s["sid"], unit["id"], checked[0], s["base_url"])
                        fname = checked[0]
                    else:
                        buf = BytesIO()
                        with zipfile.ZipFile(buf, "w") as z:
                            for fn in checked:
                                d = get_file(s["sid"], unit["id"], fn, s["base_url"])
                                if d: z.writestr(fn, d)
                        buf.seek(0)
                        att, fname = buf.read(), f"{unit['reg']}_{day}.zip"
                    send_mail(f"DDD fajlovi — {unit['reg']}",
                              "Izabrani fajlovi u prilogu.",
                              att, fname, s)
                    st.success("E-mail poslat!")

if __name__ == "__main__":
    main()
