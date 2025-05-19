import os, json, zipfile, threading, requests, re, smtplib, traceback, hashlib
from datetime import datetime, date, time as t, timedelta, timezone
from io import BytesIO
from email.message import EmailMessage
from urllib.parse import unquote_plus
# import base64 # Nije više potrebno za logo, ali može ostati ako zatreba za nešto drugo

import streamlit as st
from streamlit.runtime.scriptrunner import add_script_run_ctx

# ─────────── konstante ───────────
DEFAULT_TOKEN = "975449712b54d5463a9bc22eddfacb006D57EA7D1C7F73A4690338D42F14313ED12D0C1F"
DATE_RE  = re.compile(r"20\d{6}")
EU_BG    = timezone(timedelta(hours=2))
SETFILE  = "smtp_settings.json"
TIMERKEY = "auto_timer"
DEFAULT_WIALON_BASE_URL = "https://hst-api.wialon.com"

# =========== Logo URL ===========
# URL vašeg loga sa GitHub-a preko jsDelivr CDN-a
LOGO_URL = "https://cdn.jsdelivr.net/gh/Miljan2401/test2@main/app_icon.png"

# ─────────── pomoćne ────────────
def normalize_base_url(u: str) -> str:
    u = u.strip().rstrip("/")
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u + "/wialon/ajax.html" if not u.endswith("/wialon/ajax.html") else u

def sha(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

def load_settings() -> dict:
    if os.path.exists(SETFILE):
        try:
            with open(SETFILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            st.warning(f"Greška pri učitavanju podešavanja ({SETFILE}): {e}")
    return {}

def save_settings(s: dict) -> None:
    try:
        with open(SETFILE, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception as e:
        st.error(f"Greška pri čuvanju podešavanja ({SETFILE}): {e}")

def wialon_call(svc: str, sid: str, params: dict | None, base: str, *, get_method=False):
    payload = {"svc": svc, "sid": sid}
    if params is not None:
        payload["params"] = json.dumps(params, separators=(",", ":"))

    try:
        if get_method:
            r = requests.get(base, params=payload, timeout=20)
        else:
            post_data = {"svc": svc, "sid": sid}
            if params is not None:
                post_data["params"] = json.dumps(params, separators=(",", ":"))
            r = requests.post(base, data=post_data, timeout=20)
        
        r.raise_for_status()
        response_json = r.json()
        if isinstance(response_json, dict) and "error" in response_json:
            error_code = response_json.get("error")
            raise RuntimeError(f"Wialon API greška (kod: {error_code}) - {response_json}")
        return response_json
    except requests.exceptions.Timeout:
        raise RuntimeError("Wialon server nije odgovorio na vreme (timeout).")
    except requests.exceptions.ConnectionError:
        raise RuntimeError("Greška pri povezivanju sa Wialon serverom. Proverite URL i internet konekciju.")
    except requests.exceptions.HTTPError as http_err:
        # Pokušaj da se dobije više detalja iz odgovora ako je JSON
        try:
            error_details = http_err.response.json()
            detail_msg = error_details.get("reason", http_err.response.text[:200])
        except json.JSONDecodeError:
            detail_msg = http_err.response.text[:200]
        raise RuntimeError(f"HTTP greška od Wialon servera: {http_err.response.status_code} - {detail_msg}")
    except json.JSONDecodeError:
        raise RuntimeError(f"Wialon server je vratio odgovor koji nije validan JSON: {r.text[:200]}")

# ─────────── Wialon API ─────────
def login_token(token: str, base: str) -> str | None:
    try:
        r_json = wialon_call("token/login", "", {"token": token}, base, get_method=True)
        return r_json.get("eid")
    except RuntimeError as e:
        st.error(f"Greška pri prijavi tokenom: {e}")
        return None
    except Exception as e: # Druge neočekivane greške
        st.error(f"Neočekivana greška prilikom prijave tokenom: {e}")
        return None

def get_units(sid: str, base: str):
    # Flags: 0x01 (base properties), 0x8000 (custom properties like 'reg_number')
    res = wialon_call("core/search_items", sid,
        {"spec": {"itemsType": "avl_unit", "propName": "sys_name",
                  "propValueMask": "*", "sortType": "sys_name"},
         "force": 1, "flags": 0x01 | 0x8000, "from": 0, "to": 0},
        base)
    return [{"id": it["id"],
             "name": it.get("nm", "N/A"),
             "reg": it.get("prp", {}).get("reg_number", "") or it.get("prms", {}).get("reg_number", {}).get("v", "")}
            for it in res.get("items", [])]

def list_files(sid: str, uid: int, day: date, base: str):
    res = wialon_call("file/list", sid,
        {"itemId": uid, "storageType": 2, "path": "tachograph/",
         "mask": "*", "recursive": False, "fullPath": False}, base)
    
    out = []
    target_day_local = day

    for f_meta in res: # res je lista ako je API poziv uspešan
        if not isinstance(f_meta, dict) or "n" not in f_meta: continue

        file_date_match = False
        ts_keys_priority = ["mt", "ct"] # mt: modification time, ct: creation time
        for ts_key in ts_keys_priority:
            if ts_key in f_meta and f_meta[ts_key] is not None: # Provera da timestamp nije None
                try:
                    file_dt_utc = datetime.fromtimestamp(f_meta[ts_key], timezone.utc)
                    file_date_local = file_dt_utc.astimezone(EU_BG).date()
                    if file_date_local == target_day_local:
                        file_date_match = True; break 
                except (TypeError, ValueError, OSError) as ts_err:
                    # print(f"Greška pri konverziji timestamp-a ({ts_key}={f_meta[ts_key]}): {ts_err}") # Za debug
                    pass # Pokušaj sledeći ključ ili metod
            
        if file_date_match:
            out.append(f_meta)
        else:
            date_match_in_name = DATE_RE.search(f_meta["n"])
            if date_match_in_name:
                try:
                    if datetime.strptime(date_match_in_name.group(), "%Y%m%d").date() == target_day_local:
                        out.append(f_meta)
                except ValueError: pass # Datum u imenu nije validan

    out.sort(key=lambda x: x.get("mt", x.get("ct", 0)), reverse=True)
    return out

def get_file(sid: str, uid: int, fname: str, base: str) -> bytes | None:
    params_payload = {"itemId": uid, "storageType": 2, "path": f"tachograph/{fname}"}
    try:
        r = requests.get(base,
            params={"svc": "file/get", "sid": sid, "params": json.dumps(params_payload)}, 
            timeout=60) # Povećan timeout za download fajlova
        r.raise_for_status()
        content_type = r.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                json_error = r.json()
                if "error" in json_error:
                    st.error(f"Wialon API greška (file/get) za {fname}: {json_error}")
                    return None
            except json.JSONDecodeError: pass
        return r.content
    except requests.exceptions.Timeout:
        st.error(f"Timeout pri preuzimanju fajla {fname}.")
    except requests.exceptions.RequestException as e:
        st.error(f"Greška pri preuzimanju fajla {fname}: {e}")
    return None

# ─────────── SMTP & auto-task ───────────
def send_mail(subj: str, body: str, att: bytes | None,
              fname_att: str, s_settings: dict):
    if not all(s_settings.get(k) for k in ["server", "port", "username", "password", "recipients"]):
        st.error("SMTP podešavanja nisu kompletna. Proverite Admin panel.")
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subj
        msg["From"] = s_settings["username"]
        # Osiguraj da su primaoci lista stringova, bez praznih
        recipients_list = [r.strip() for r in s_settings["recipients"].split(',') if r.strip()]
        if not recipients_list:
            st.error("Nema primalaca e-maila definisanih u SMTP podešavanjima.")
            return False
        msg["To"] = recipients_list
        msg.set_content(body)
        
        if att and fname_att:
            maintype, subtype = "application", "octet-stream"
            if fname_att.lower().endswith(".zip"): subtype = "zip"
            # Dodatni MIME tipovi mogu biti dodati ovde
            msg.add_attachment(att, maintype=maintype, subtype=subtype, filename=fname_att)
        
        # Provera da li je port broj
        try:
            port_num = int(s_settings["port"])
        except ValueError:
            st.error(f"SMTP Port '{s_settings['port']}' nije validan broj.")
            return False

        with smtplib.SMTP(s_settings["server"], port_num, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(s_settings["username"], s_settings["password"])
            smtp.send_message(msg)
        return True
    except smtplib.SMTPAuthenticationError:
        st.error("SMTP greška: Autentifikacija nije uspela. Proverite korisničko ime i lozinku.")
    except smtplib.SMTPServerDisconnected:
        st.error("SMTP greška: Server je prekinuo vezu.")
    except (smtplib.SMTPException, ConnectionRefusedError, OSError) as e: # Hvata šire SMTP i mrežne greške
        st.error(f"SMTP/Mrežna greška: {e}")
    except Exception as e: # Sve ostale greške
        st.error(f"Neočekivana greška prilikom slanja e-maila: {e}")
        traceback.print_exc() # Za debugovanje u konzoli servera
    return False

def schedule_nightly(app_base_url: str): # app_base_url je Wialon base URL
    tmr: threading.Timer | None = st.session_state.get(TIMERKEY)
    if tmr and tmr.is_alive(): tmr.cancel()

    s_settings = st.session_state.get("settings", {})
    if not s_settings.get("auto_send"): return

    now_eu = datetime.now(EU_BG)
    run_time_eu = t(2, 5, tzinfo=EU_BG) # Vreme izvršavanja: 02:05h
    run_dt_eu = datetime.combine(now_eu.date(), run_time_eu)
    if now_eu.time() >= run_time_eu: # Ako je već prošlo 02:05h danas
        run_dt_eu += timedelta(days=1) # Planiraj za sutra
        
    delay_seconds = (run_dt_eu - now_eu).total_seconds()
    if delay_seconds < 0: delay_seconds = 0 # Za slučaj da je vreme "skoro" isto

    # Upisivanje poruka u session_state da bi se prikazale u glavnom threadu
    if "messages_from_scheduler" not in st.session_state: st.session_state.messages_from_scheduler = []
    st.session_state.messages_from_scheduler.append(f"INFO: Automatsko slanje zakazano za: {run_dt_eu.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    def job():
        job_start_time_str = datetime.now(EU_BG).strftime('%Y-%m-%d %H:%M:%S')
        # Poruke iz job-a se takođe pišu u session_state
        if "messages_from_job" not in st.session_state: st.session_state.messages_from_job = []
        st.session_state.messages_from_job.append(f"--- [{job_start_time_str}] Započinjanje automatskog preuzimanja DDD fajlova ---")
        
        try:
            current_s = load_settings() # Uvek učitaj najsvežija podešavanja unutar thread-a
            if not current_s.get("auto_send"):
                st.session_state.messages_from_job.append("INFO: Automatsko slanje je isključeno u međuvremenu. Zadatak prekinut.")
                return

            sid, wialon_base = current_s.get("sid"), current_s.get("base_url")
            if not sid or not wialon_base:
                st.session_state.messages_from_job.append("GREŠKA: SID ili Wialon base URL nisu dostupni za automatski zadatak.")
                return

            units = get_units(sid, wialon_base)
            if not units:
                st.session_state.messages_from_job.append("INFO: Nema vozila za obradu u automatskom zadatku.")
                # Možda poslati email i o ovome?
                return

            prev_day_date = (datetime.now(EU_BG) - timedelta(days=1)).date()
            all_files_to_zip = [] # Lista parova (zip_path, file_data)
            
            st.session_state.messages_from_job.append(f"INFO: Preuzimanje fajlova za dan: {prev_day_date.strftime('%d.%m.%Y')} za {len(units)} vozila.")

            for u_item in units:
                unit_name_for_path = u_item["reg"] or u_item["name"]
                unit_name_for_path = "".join(c for c in unit_name_for_path if c.isalnum() or c in (' ', '_', '-')).strip() or f"unit_{u_item['id']}"

                try:
                    files_for_unit = list_files(sid, u_item["id"], prev_day_date, wialon_base)
                    if files_for_unit:
                        st.session_state.messages_from_job.append(f"INFO: Za vozilo {unit_name_for_path} pronađeno {len(files_for_unit)} fajlova.")
                    for f_meta_item in files_for_unit:
                        file_data = get_file(sid, u_item["id"], f_meta_item["n"], wialon_base)
                        if file_data:
                            zip_path = os.path.join(unit_name_for_path, f_meta_item["n"])
                            all_files_to_zip.append((zip_path, file_data))
                        else:
                            st.session_state.messages_from_job.append(f"UPOZORENJE: Nije uspelo preuzimanje fajla {f_meta_item['n']} za vozilo {unit_name_for_path}")
                except Exception as e_unit_processing:
                    st.session_state.messages_from_job.append(f"GREŠKA pri obradi vozila {unit_name_for_path}: {str(e_unit_processing)[:100]}") # Skraćena poruka

            if not all_files_to_zip:
                st.session_state.messages_from_job.append("INFO: Nema fajlova za slanje nakon pretrage svih vozila.")
                subject_no_files = f"DDD fajlovi {prev_day_date.strftime('%d.%m.%Y')} - Nema podataka"
                body_no_files = "Automatski zadatak je izvršen, ali nisu pronađeni DDD fajlovi za prethodni dan za bilo koje vozilo."
                send_mail(subject_no_files, body_no_files, None, "", current_s)
                return

            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for zip_path, data_bytes in all_files_to_zip:
                    zf.writestr(zip_path, data_bytes)
            zip_buffer.seek(0)
            
            zip_filename = f"DDD_SvaVozila_{prev_day_date.strftime('%Y%m%d')}.zip"
            mail_subject = f"DDD fajlovi za {prev_day_date.strftime('%d.%m.%Y')}"
            mail_body = f"Automatski generisana ZIP arhiva sa {len(all_files_to_zip)} DDD fajlova za dan {prev_day_date.strftime('%d.%m.%Y')}."
            
            st.session_state.messages_from_job.append(f"INFO: Slanje email-a sa {len(all_files_to_zip)} fajlova u ZIP arhivi: {zip_filename}")
            if send_mail(mail_subject, mail_body, zip_buffer.read(), zip_filename, current_s):
                st.session_state.messages_from_job.append("USPEH: Automatski email sa DDD fajlovima uspešno poslat.")
            else:
                 st.session_state.messages_from_job.append("GREŠKA: Automatski email NIJE poslat zbog greške u slanju.")

        except RuntimeError as e_runtime_job:
            st.session_state.messages_from_job.append(f"WIALON GREŠKA u automatskom zadatku: {e_runtime_job}")
            traceback.print_exc()
        except Exception as e_job:
            st.session_state.messages_from_job.append(f"NEOČEKIVANA GREŠKA u automatskom zadatku: {e_job}")
            traceback.print_exc()
        finally:
            st.session_state.messages_from_job.append(f"--- [{datetime.now(EU_BG).strftime('%H:%M:%S')}] Automatski zadatak završen ---")
            # Ponovno zakazivanje
            final_s = load_settings()
            if final_s.get("auto_send"):
                schedule_nightly(final_s.get("base_url", DEFAULT_WIALON_BASE_URL))
            else:
                if "messages_from_scheduler" not in st.session_state: st.session_state.messages_from_scheduler = []
                st.session_state.messages_from_scheduler.append("INFO: Automatsko slanje je isključeno, noćni zadatak se ne zakazuje ponovo.")

    tmr = threading.Timer(delay_seconds, job)
    tmr.daemon = True
    add_script_run_ctx(tmr)
    tmr.start()
    st.session_state[TIMERKEY] = tmr

# ─────────── UI ───────────
def set_bg_from_url(image_url: str):
    # Provera da li je URL placeholder ili prazan
    if not image_url or "PLACEHOLDER" in image_url.upper() or image_url == "https://cdn.jsdelivr.net/gh/Miljan2401/test2@main/app_icon.png" and "test2" in image_url : # Ako je i dalje default testni logo
        if image_url != "https://cdn.jsdelivr.net/gh/Miljan2401/test2@main/app_icon.png": # Ne prikazuj za testni
            st.sidebar.warning("LOGO NIJE ISPRAVNO PODEŠEN! Proverite LOGO_URL konstantu u kodu.")
        # Možemo odlučiti da ne postavljamo CSS ako logo nije validan
        # return 
    
    # Za testiranje, možete privremeno povećati opacity
    # opacity_val = 0.5 # Test vrednost
    opacity_val = 0.05 # Produkciona vrednost

    page_bg_img_css = f'''
    <style>
    body::before {{
        content: "";
        position: fixed;
        left: 0;
        top: 0;
        width: 100vw;
        height: 100vh;
        background-image: url("{image_url}");
        background-repeat: no-repeat;
        background-position: center center;
        background-size: contain;
        opacity: {opacity_val};
        z-index: -1;
        pointer-events: none;
    }}
    .stApp {{
        background-color: transparent !important;
    }}
    [data-testid="stSidebar"], [data-testid="stHeader"] {{
        background-color: rgba(240, 242, 246, 0.85) !important;
    }}
    html[data-theme="dark"] [data-testid="stSidebar"],
    html[data-theme="dark"] [data-testid="stHeader"] {{
         background-color: rgba(40, 43, 54, 0.85) !important;
    }}
    </style>
    '''
    st.markdown(page_bg_img_css, unsafe_allow_html=True)

def main():
    st.set_page_config("Wialon DDD Manager", layout="wide", initial_sidebar_state="expanded")

    set_bg_from_url(LOGO_URL)

    # Prikaz poruka iz scheduler-a i job-a
    if "messages_from_scheduler" in st.session_state and st.session_state.messages_from_scheduler:
        for msg_sched in st.session_state.messages_from_scheduler: st.sidebar.caption(msg_sched)
        st.session_state.messages_from_scheduler = []

    if "messages_from_job" in st.session_state and st.session_state.messages_from_job:
        with st.sidebar.expander("Log automatskog zadatka", expanded=False):
            for msg_job in st.session_state.messages_from_job: st.write(msg_job)
        # Ne brisati messages_from_job odmah, možda korisnik želi da ih vidi kasnije
        # Možda dodati dugme "Obriši log" ili brisati pri sledećem pokretanju job-a

    # Čitanje query parametara - potvrđeno da koristi st.query_params
    raw_query_base_url = st.query_params.get("baseUrl") 
    wialon_base_url_from_query = DEFAULT_WIALON_BASE_URL # Default ako nema iz query-ja
    if raw_query_base_url:
        wialon_base_url_from_query = normalize_base_url(unquote_plus(raw_query_base_url))
    
    sid_from_query = st.query_params.get("sid")

    if "settings" not in st.session_state:
        st.session_state["settings"] = load_settings()
    
    s_settings = st.session_state["settings"]
    # Postavi base_url iz query-ja ako postoji, inače iz podešavanja, inače default
    s_settings["base_url"] = wialon_base_url_from_query if raw_query_base_url else s_settings.get("base_url", DEFAULT_WIALON_BASE_URL)
    if not s_settings.get("base_url"): # Još jedna provera da nije prazan
        s_settings["base_url"] = DEFAULT_WIALON_BASE_URL

    if sid_from_query: 
        s_settings["sid"] = sid_from_query
        # Možda sačuvati podešavanja ako je SID došao iz URL-a?
        # save_settings(s_settings)

    current_sid = s_settings.get("sid")
    wialon_api_base = s_settings.get("base_url", DEFAULT_WIALON_BASE_URL) # Koristi default ako nije postavljen

    sid_is_valid = False
    if current_sid:
        try:
            # Lagani test poziv da se vidi da li je SID validan
            wialon_call("core/get_server_time", current_sid, {}, wialon_api_base) 
            sid_is_valid = True
        except RuntimeError as e:
            st.sidebar.error(f"SID ({str(current_sid)[:10]}...) nije validan ili je istekao: {e}. Molimo prijavite se ponovo.")
            s_settings.pop("sid", None); current_sid = None; save_settings(s_settings) # Ukloni nevalidan SID
            # Otkaži tajmer ako je bio aktivan
            tmr_check: threading.Timer | None = st.session_state.get(TIMERKEY)
            if tmr_check and tmr_check.is_alive():
                tmr_check.cancel(); st.session_state.pop(TIMERKEY, None)
                st.sidebar.info("Automatsko slanje zaustavljeno (nevalidan SID).")
        except Exception as e_sid_check: # Druge greške (npr. mreža)
            st.sidebar.warning(f"Greška pri proveri SID-a: {e_sid_check}. Možda privremeni problem sa mrežom.")

    # Inicijalno pokretanje tajmera ako su uslovi ispunjeni
    if s_settings.get("auto_send") and sid_is_valid: # Samo ako je SID validan
        # Pokreni samo ako tajmer već ne postoji ili nije živ
        if not st.session_state.get(TIMERKEY) or not st.session_state.get(TIMERKEY).is_alive():
             schedule_nightly(s_settings["base_url"])

    page = st.sidebar.radio("Navigacija", ["Preuzimanje Fajlova", "Administracija"], key="main_navigation_menu")

    # --- ADMIN PANEL ---
    if page == "Administracija":
        st.header("🔐 Admin Panel")
        admin_password_set = bool(s_settings.get("admin_pw_hash"))
        if admin_password_set: # Ako je admin lozinka postavljena
            if not st.session_state.get("admin_ok", False): # Ako korisnik nije ulogovan kao admin
                admin_pwd_input = st.sidebar.text_input("Admin lozinka", type="password", key="admin_panel_login_pwd")
                if st.sidebar.button("Login u Admin Panel", key="admin_panel_login_btn"):
                    if sha(admin_pwd_input) == s_settings["admin_pw_hash"]:
                        st.session_state["admin_ok"] = True; st.experimental_rerun()
                    else: st.sidebar.error("Pogrešna admin lozinka.")
                st.info("Unesite admin lozinku u sidebar-u za pristup administrativnim podešavanjima.")
                st.stop() # Ne prikazuj ostatak admin panela dok se ne uloguje
        else: # Prvo postavljanje admin lozinke
            st.sidebar.info("Admin lozinka još uvek nije postavljena. Molimo postavite je da biste osigurali podešavanja.")
            new_admin_pwd_initial = st.sidebar.text_input("Postavi novu Admin lozinku", type="password", key="admin_set_initial_password")
            if st.sidebar.button("Sačuvaj Admin lozinku", key="admin_set_initial_password_btn"):
                if new_admin_pwd_initial:
                    s_settings["admin_pw_hash"] = sha(new_admin_pwd_initial)
                    save_settings(s_settings)
                    st.session_state["admin_ok"] = True # Automatski login nakon postavljanja
                    st.sidebar.success("Admin lozinka uspešno postavljena."); st.experimental_rerun()
                else: st.sidebar.error("Admin lozinka ne može biti prazna.")
            st.stop() # Ne prikazuj ostatak dok se lozinka ne postavi

        # Ako smo došli dovde, korisnik je admin (ili je upravo postavio lozinku)
        with st.expander("Promena Admin Lozinke", expanded=False):
            change_admin_pwd_input = st.text_input("Unesite novu admin lozinku", type="password", key="admin_change_password_input_field")
            if st.button("Sačuvaj novu admin lozinku", key="admin_change_password_button"):
                if change_admin_pwd_input:
                    s_settings["admin_pw_hash"] = sha(change_admin_pwd_input)
                    save_settings(s_settings)
                    st.success("Admin lozinka uspešno promenjena.")
                else:
                    st.error("Nova admin lozinka ne može biti prazna.")
        
        st.subheader("Wialon Podešavanja")
        s_settings["base_url"] = normalize_base_url(st.text_input("Wialon Base URL", s_settings.get("base_url", DEFAULT_WIALON_BASE_URL), key="wialon_url_admin_config"))
        s_settings["token"] = st.text_input("Wialon Token (za prijavu)", s_settings.get("token", DEFAULT_TOKEN), type="password", key="wialon_token_admin_config", help="Token za automatsku prijavu ako SID istekne ili nije prisutan.")
        
        st.subheader("SMTP Podešavanja za Slanje E-maila")
        s_settings["server"] = st.text_input("SMTP Server", s_settings.get("server", ""), key="smtp_server_config")
        s_settings["port"]   = st.text_input("SMTP Port",   s_settings.get("port", "587"), key="smtp_port_config")
        s_settings["username"]= st.text_input("SMTP Korisničko ime", s_settings.get("username", ""), key="smtp_user_config")
        s_settings["password"]= st.text_input("SMTP Lozinka", s_settings.get("password", ""), type="password", key="smtp_pass_config")
        s_settings["recipients"]= st.text_input("Primaoci E-maila (odvojeni zarezom)", s_settings.get("recipients", ""), key="smtp_recipients_config", help="npr. Pera <pera@ primer.com>, mika@primer.com")

        auto_send_current_val = s_settings.get("auto_send", False)
        auto_send_new_val = st.checkbox("Noćno automatsko slanje e-maila (oko 02:05h)", value=auto_send_current_val, key="auto_send_checkbox_admin_page")
        if auto_send_new_val != auto_send_current_val: # Ako je došlo do promene stanja checkboxa
            s_settings["auto_send"] = auto_send_new_val
            if auto_send_new_val and sid_is_valid: # Ako je uključeno i SID postoji i validan je
                schedule_nightly(s_settings["base_url"])
                st.info("Automatsko slanje aktivirano i zakazano.")
            elif not auto_send_new_val: # Ako je isključeno
                tmr_admin_toggle: threading.Timer | None = st.session_state.get(TIMERKEY)
                if tmr_admin_toggle and tmr_admin_toggle.is_alive():
                    tmr_admin_toggle.cancel()
                    st.session_state.pop(TIMERKEY, None)
                st.info("Automatsko slanje deaktivirano.")
            # Nema potrebe za save_settings(s_settings) ovde, to će uraditi dugme "Sačuvaj"

        admin_col1, admin_col2, admin_col3 = st.columns(3)
        with admin_col1:
            if st.button("Sačuvaj Podešavanja", key="admin_save_settings_button", type="primary"):
                save_settings(s_settings)
                st.success("Podešavanja su sačuvana.")
                # Ako je auto_send uključen i SID validan, osiguraj da je tajmer pokrenut
                if s_settings.get("auto_send") and sid_is_valid:
                     if not st.session_state.get(TIMERKEY) or not st.session_state.get(TIMERKEY).is_alive():
                        schedule_nightly(s_settings["base_url"])
                st.experimental_rerun() 
        with admin_col2:
            if st.button("Testiraj E-mail Podešavanja", key="admin_test_email_config_button"):
                if send_mail("Test Wialon DDD Manager", "Ovo je test poruka za proveru SMTP podešavanja.", None, "", s_settings):
                    st.success("Test e-mail uspešno poslat!")
        with admin_col3:
            if st.button("Odjava iz Admin Panela", key="admin_panel_logout_button"):
                st.session_state.pop("admin_ok", None)
                st.experimental_rerun()
                
    # --- PREUZIMANJE FAJLOVA PANEL ---
    elif page == "Preuzimanje Fajlova":
        st.header("📁 Preuzimanje DDD Fajlova")

        if not current_sid or not sid_is_valid: # Ako SID ne postoji ili nije validan
            st.subheader("Prijava na Wialon")
            login_token_val = s_settings.get("token", DEFAULT_TOKEN)
            if not login_token_val:
                 st.warning("Wialon token nije podešen. Molimo unesite token u Admin panelu.")
            
            if st.button("Prijavi se koristeći Wialon Token", key="manual_login_button_files_page", disabled=not login_token_val, type="primary"):
                sid_new = login_token(login_token_val, wialon_api_base)
                if sid_new:
                    s_settings["sid"] = sid_new; current_sid = sid_new; sid_is_valid = True # Ažuriraj lokalne promenljive
                    save_settings(s_settings) # Sačuvaj novi SID
                    st.success("Uspešno prijavljen na Wialon!")
                    if s_settings.get("auto_send"): # Ako je auto_send aktivan, pokreni tajmer
                        schedule_nightly(s_settings["base_url"])
                    st.experimental_rerun()
            st.markdown("---")
            st.info("SID sesija nije aktivna ili je istekla. Koristite dugme iznad za prijavu tokenom. Token i Wialon URL se podešavaju u Admin panelu.")
            st.stop()
        
        # Ako smo ovde, SID je validan
        try:
            units = get_units(current_sid, wialon_api_base)
            if not units:
                st.warning("Nema dostupnih vozila (jedinica) na vašem Wialon nalogu.")
                st.stop()
        except RuntimeError as e:
            st.error(f"Wialon API greška pri dobavljanju liste vozila: {e}")
            st.stop()
        except Exception as e: # Hvata ostale nepredviđene greške
            st.error(f"Neočekivana greška prilikom dobavljanja liste vozila: {e}")
            traceback.print_exc()
            st.stop()

        col_left_files, col_right_files = st.columns([1, 2])

        with col_left_files:
            st.subheader("Izbor Vozila i Datuma")
            default_file_date = (datetime.now(EU_BG) - timedelta(days=1)).date() # Jučerašnji datum kao default
            selected_day = st.date_input("Datum za pretragu fajlova", value=default_file_date, key="file_date_selector_input", help="Birate datum za koji želite DDD fajlove.")
            
            search_query = st.text_input("Pretraga vozila (ime/registracija)", "", placeholder="Unesite deo imena ili registracije...", key="vehicle_search_input_field").lower()
            
            filtered_units = [
                u for u in units 
                if search_query in (u.get("reg", "") + u.get("name", "")).lower()
            ]
            
            if not filtered_units:
                st.warning("Nema vozila koja odgovaraju unetoj pretrazi.")
                st.stop()

            unit_options_display = []
            unit_map_for_selection = {} # Mapiranje display stringa na unit ID
            for i, u_item in enumerate(filtered_units):
                reg_no = u_item.get('reg', 'Nema Reg.')
                name_no = u_item.get('name', 'Nema Imena')
                display_str_base = f"{reg_no} — {name_no}"
                
                # Osiguravanje jedinstvenosti labela za radio dugmad
                display_str_final = display_str_base
                counter = 1
                while display_str_final in unit_map_for_selection:
                    display_str_final = f"{display_str_base} ({counter})"
                    counter += 1
                
                unit_options_display.append(display_str_final)
                unit_map_for_selection[display_str_final] = u_item['id']
            
            if not unit_options_display: # Dodatna provera
                st.warning("Nema vozila za prikaz nakon filtriranja i formiranja labela.")
                st.stop()
                
            selected_unit_display_str = st.radio(
                "Izaberite vozilo:", unit_options_display, index=0, key="vehicle_radio_selector_list"
            )
            
            selected_unit_id = unit_map_for_selection.get(selected_unit_display_str)
            selected_unit = next((u for u in filtered_units if u['id'] == selected_unit_id), None)

            if not selected_unit:
                st.error("Greška pri izboru vozila. Molimo osvežite stranicu ili pokušajte ponovo."); st.stop()

        with col_right_files:
            unit_display_name_files = selected_unit.get("reg") or selected_unit.get("name") or f"ID: {selected_unit['id']}"
            st.subheader(f"Fajlovi za: **{unit_display_name_files}**")
            st.markdown(f"Datum: **{selected_day.strftime('%d.%m.%Y')}**")

            try:
                listed_files = list_files(current_sid, selected_unit["id"], selected_day, wialon_api_base)
            except RuntimeError as e: st.error(f"Wialon API greška pri listanju fajlova: {e}"); st.stop()
            except Exception as e: st.error(f"Neočekivana greška pri listanju fajlova: {e}"); traceback.print_exc(); st.stop()

            if not listed_files: st.info("Nema dostupnih fajlova za izabrano vozilo i datum."); st.stop()

            st.markdown("##### Izaberite fajlove za akciju:")
            # Ključ za session_state checkbox-ova, jedinstven po vozilu i danu
            checkbox_state_key_prefix = f"cb_sel_state_{selected_unit['id']}_{selected_day.isoformat()}_"
            
            sel_col1_f, sel_col2_f = st.columns(2)
            # "Označi sve" / "Poništi sve" logika
            if sel_col1_f.button("Označi sve fajlove", key=f"select_all_files_button_{selected_unit['id']}_{selected_day}"):
                for f_meta_item in listed_files: st.session_state[f"{checkbox_state_key_prefix}{f_meta_item['n']}"] = True
                st.experimental_rerun() # Osveži da se prikažu označeni checkbox-ovi

            if sel_col2_f.button("Poništi sve oznake", key=f"deselect_all_files_button_{selected_unit['id']}_{selected_day}"):
                for f_meta_item in listed_files: st.session_state[f"{checkbox_state_key_prefix}{f_meta_item['n']}"] = False
                st.experimental_rerun()

            selected_file_names_for_action = []
            for f_meta_item in listed_files:
                cb_key = f"{checkbox_state_key_prefix}{f_meta_item['n']}"
                # Vrednost checkbox-a se uzima iz session_state ako postoji, inače False
                is_checked = st.checkbox(
                    f"{f_meta_item['n']} (Veličina: {f_meta_item.get('s', 0)//1024:.1f} KB, Mod: {datetime.fromtimestamp(f_meta_item.get('mt', f_meta_item.get('ct', 0)), EU_BG).strftime('%H:%M') if f_meta_item.get('mt') or f_meta_item.get('ct') else 'N/A'})", 
                    value=st.session_state.get(cb_key, False), 
                    key=cb_key # Streamlit će automatski ažurirati session_state[cb_key]
                )
                if is_checked:
                    selected_file_names_for_action.append(f_meta_item['n'])
            
            st.markdown("---")
            if not selected_file_names_for_action:
                st.info("Niste izabrali nijedan fajl za preuzimanje ili slanje."); st.stop()

            st.markdown(f"**Izabrano fajlova: {len(selected_file_names_for_action)}**")
            action_col_dl, action_col_email = st.columns(2)
            
            # Sanitizacija imena za preuzete fajlove
            safe_unit_name_dl = "".join(c for c in unit_display_name_files if c.isalnum() or c in ('_', '-')).strip('_') or "fajl_jedinice"

            with action_col_dl: # DOWNLOAD Akcija
                if len(selected_file_names_for_action) == 1:
                    single_fname_to_dl = selected_file_names_for_action[0]
                    # Koristimo st.button da iniciramo preuzimanje, a st.download_button za samo preuzimanje
                    # Ovo je malo zaobilazno, ali daje bolju kontrolu nad UI pre nego što se fajl preuzme
                    if st.button(f"📥 Preuzmi: {single_fname_to_dl}", key=f"download_single_file_btn_{single_fname_to_dl}"):
                        with st.spinner(f"Preuzimanje fajla {single_fname_to_dl}..."):
                            file_bytes_for_dl = get_file(current_sid, selected_unit["id"], single_fname_to_dl, wialon_api_base)
                        if file_bytes_for_dl:
                            st.download_button(
                                label=f"Kliknite da preuzmete {single_fname_to_dl}",
                                data=file_bytes_for_dl,
                                file_name=single_fname_to_dl,
                                mime="application/octet-stream",
                                key=f"actual_download_button_single_{single_fname_to_dl}" # Jedinstven ključ
                            )
                            st.success(f"Fajl {single_fname_to_dl} je spreman.")
                        else:
                            st.error(f"Nije uspelo preuzimanje fajla {single_fname_to_dl}.")
                else: # Više fajlova -> ZIP
                    zip_filename_for_dl = f"{safe_unit_name_dl}_{selected_day.strftime('%Y%m%d')}.zip"
                    if st.button(f"📥 Preuzmi ZIP ({len(selected_file_names_for_action)} fajlova)", key=f"download_zip_files_button"):
                        zip_buffer_for_dl = BytesIO()
                        with st.spinner(f"Kreiranje ZIP arhive za {len(selected_file_names_for_action)} fajlova..."):
                            with zipfile.ZipFile(zip_buffer_for_dl, "w", zipfile.ZIP_DEFLATED) as zf_dl:
                                for i, fname_to_zip_dl in enumerate(selected_file_names_for_action):
                                    file_bytes_for_zip_dl = get_file(current_sid, selected_unit["id"], fname_to_zip_dl, wialon_api_base)
                                    if file_bytes_for_zip_dl:
                                        zf_dl.writestr(fname_to_zip_dl, file_bytes_for_zip_dl)
                                    else:
                                        st.warning(f"Fajl {fname_to_zip_dl} nije mogao biti preuzet i dodat u ZIP arhivu.")
                        zip_buffer_for_dl.seek(0)
                        st.download_button(
                            label=f"Kliknite da preuzmete {zip_filename_for_dl}",
                            data=zip_buffer_for_dl,
                            file_name=zip_filename_for_dl,
                            mime="application/zip",
                            key=f"actual_download_button_zip" # Jedinstven ključ
                        )
                        st.success(f"ZIP arhiva {zip_filename_for_dl} je spremna.")
            
            with action_col_email: # EMAIL Akcija
                email_button_label = f"📧 Pošalji E-mail ({len(selected_file_names_for_action)} fajl{'a' if 1 < len(selected_file_names_for_action) < 5 else 'ova'})"
                if st.button(email_button_label, key=f"email_selected_files_button"):
                    if not all(s_settings.get(k) for k in ["server", "port", "username", "password", "recipients"]):
                        st.error("SMTP podešavanja nisu kompletna. Molimo proverite Admin panel pre slanja emaila.")
                    else:
                        attachment_bytes_for_email = None
                        attachment_filename_for_email = ""
                        email_subject = f"DDD fajlovi za vozilo: {unit_display_name_files} (Datum: {selected_day.strftime('%d.%m.%Y')})"
                        email_body = f"U prilogu se nalaze izabrani DDD fajlovi za vozilo {unit_display_name_files} za datum {selected_day.strftime('%d.%m.%Y')}.\n\nIzabrani fajlovi:\n" + "\n".join(selected_file_names_for_action)

                        with st.spinner("Priprema fajlova za slanje emailom..."):
                            if len(selected_file_names_for_action) == 1:
                                single_fname_for_email = selected_file_names_for_action[0]
                                attachment_bytes_for_email = get_file(current_sid, selected_unit["id"], single_fname_for_email, wialon_api_base)
                                attachment_filename_for_email = single_fname_for_email
                            else: # ZIP za više fajlova
                                zip_buffer_for_email = BytesIO()
                                with zipfile.ZipFile(zip_buffer_for_email, "w", zipfile.ZIP_DEFLATED) as zf_email:
                                    for fname_to_email_zip in selected_file_names_for_action:
                                        file_bytes_for_email_zip = get_file(current_sid, selected_unit["id"], fname_to_email_zip, wialon_api_base)
                                        if file_bytes_for_email_zip:
                                            zf_email.writestr(fname_to_email_zip, file_bytes_for_email_zip)
                                zip_buffer_for_email.seek(0)
                                attachment_bytes_for_email = zip_buffer_for_email.read()
                                attachment_filename_for_email = f"{safe_unit_name_dl}_{selected_day.strftime('%Y%m%d')}_email.zip"
                        
                        if attachment_bytes_for_email:
                            if send_mail(email_subject, email_body, attachment_bytes_for_email, attachment_filename_for_email, s_settings):
                                st.success("E-mail uspešno poslat!")
                        else:
                            st.error("Nije bilo moguće pripremiti fajlove za slanje e-mailom (možda su prazni ili je došlo do greške pri preuzimanju).")
        
        st.markdown("---")
        st.caption("""
        **Napomene:**
        - Za obradu DDD fajlova (analiza aktivnosti vozača, prekršaji, itd.) koristite specijalizovani softver. Ova aplikacija služi samo za preuzimanje fajlova sa Wialon platforme.
        - Ako automatsko noćno slanje ne radi, proverite da li je SID validan (prijavite se ponovo ako je potrebno) i da li su SMTP podešavanja ispravna u Admin panelu.
        - Da bi aplikacija ostala "budna" na Streamlit Community Cloud-u, razmislite o korišćenju eksternog "ping" servisa kao što je UptimeRobot.
        """)

# ─────────── entrypoint ───────────
if __name__ == "__main__":
    main()
