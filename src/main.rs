use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::Duration;

use regex::bytes::{Regex, RegexBuilder};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use x509_parser::prelude::parse_x509_certificate;

const OLD: &[u8] = b"ineligible";
const NEW: &[u8] = b"inexigible";
const SUPPORT_URL: &str = "https://t.me/+_jsj3pvTqwc4Yzg6";

const GATE_HOSTS: &[&str] = &[
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "aicode.googleapis.com",
];
const AUTH_HOST: &str = "oauth2.googleapis.com";

const JS_PATTERN: &str = concat!(
    r#"async\s+([A-Za-z_$0-9]+)\(([A-Za-z_$0-9]+)\)\s*\{\s*"#,
    r#"if\(this\.([A-Za-z_$0-9]+)\.send\(\{type:[A-Za-z_$0-9]+\.isGcpTos\?"#,
    r#""GCP_SIGN_IN":"SIGN_IN"\}\),this\.([A-Za-z_$0-9]+)\.resetIsTierGCPTos\(\),"#,
    r#"this\.[A-Za-z_$0-9]+\.isGoogleInternal\)\{try\{"#,
    r#"await this\.([A-Za-z_$0-9]+)\.loadCodeAssist\([A-Za-z_$0-9]+\);"#,
    r#"const\{settings:([A-Za-z_$0-9]+),userTier:([A-Za-z_$0-9]+)\}="#,
    r#"await this\.refreshUserStatus\([A-Za-z_$0-9]+\),"#,
    r#"([A-Za-z_$0-9]+)=([A-Za-z_$0-9]+)\([A-Za-z_$0-9]+\);"#,
    r#"this\.([A-Za-z_$0-9]+)\.pushUpdate\([A-Za-z_$0-9]+\),"#,
    r#"this\.[A-Za-z_$0-9]+\.send\(\{type:"AUTH_SUCCESS",tokenInfo:[A-Za-z_$0-9]+\}\),"#,
    r#"this\.([A-Za-z_$0-9]+)\.fire\(\{settings:[A-Za-z_$0-9]+,userTier:[A-Za-z_$0-9]+\}\)\}"#,
    r#"catch\(([A-Za-z_$0-9]+)\)\{.*?(?:return\}|return;\s*\})"#
);

fn js_regex() -> Regex {
    RegexBuilder::new(JS_PATTERN).unicode(false).build().expect("valid regex")
}

// --- SHA-1 (совместим с backup_key из Python-версии) -----------------------

fn sha1_hex12(input: &[u8]) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    format!("{:08x}{:08x}", h[0], h[1])[..12].to_string()
}

// --- пути и поиск целей ----------------------------------------------------

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn backup_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("backup")))
        .unwrap_or_else(|| PathBuf::from("backup"))
}

fn backup_key(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        sha1_hex12(s.to_lowercase().as_bytes())
    } else {
        sha1_hex12(s.as_bytes())
    }
}

fn backup_path(p: &Path) -> PathBuf {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("target");
    backup_dir().join(format!("{name}.{}", backup_key(p)))
}

fn ensure_backup(p: &Path) -> io::Result<PathBuf> {
    let dir = backup_dir();
    fs::create_dir_all(&dir)?;
    let dst = backup_path(p);
    if !dst.exists() {
        fs::copy(p, &dst)?;
    }
    Ok(dst)
}

fn paths_file() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("paths.txt")))
        .unwrap_or_else(|| PathBuf::from("paths.txt"))
}

fn clean_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'');
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    PathBuf::from(trimmed)
}

fn load_saved_paths() -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(paths_file()) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(clean_path)
        .collect()
}

fn expand_custom_path(p: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut bins = Vec::new();
    let mut jss = Vec::new();
    if p.is_file() {
        let is_js = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("js"))
            .unwrap_or(false);
        if is_js {
            jss.push(p.to_path_buf());
        } else {
            bins.push(p.to_path_buf());
        }
        return (bins, jss);
    }
    if p.is_dir() {
        for sub in [
            p.join("resources").join("bin"),
            p.join("resources").join("app").join("extensions").join("antigravity").join("bin"),
            p.join("bin"),
            p.to_path_buf(),
        ] {
            if let Ok(entries) = fs::read_dir(&sub) {
                for entry in entries.flatten() {
                    let fp = entry.path();
                    if !fp.is_file() {
                        continue;
                    }
                    let Some(name) = fp.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    let lower = name.to_lowercase();
                    let skip_ext = lower.ends_with(".json")
                        || lower.ends_with(".js")
                        || lower.ends_with(".txt")
                        || lower.ends_with(".tmp");
                    if skip_ext {
                        continue;
                    }
                    let is_target = if cfg!(windows) {
                        (lower.starts_with("language_server") && lower.ends_with(".exe"))
                            || lower == "agy.exe"
                    } else {
                        lower.starts_with("language_server") || lower == "agy"
                    };
                    if is_target {
                        bins.push(fp);
                    }
                }
            }
        }
        let main_js = p.join("resources").join("app").join("out").join("main.js");
        if main_js.is_file() {
            jss.push(main_js);
        }
    }
    (bins, jss)
}

fn save_custom_path(raw: &str) -> String {
    let p = clean_path(raw);
    if !p.exists() {
        return format!("путь не найден: {}", p.display());
    }
    let (bins, jss) = expand_custom_path(&p);
    let saved = load_saved_paths();
    let key = if cfg!(windows) {
        p.to_string_lossy().to_lowercase()
    } else {
        p.to_string_lossy().into_owned()
    };
    let exists = saved.iter().any(|x| {
        let xk = if cfg!(windows) {
            x.to_string_lossy().to_lowercase()
        } else {
            x.to_string_lossy().into_owned()
        };
        xk == key
    });
    if !exists {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(paths_file()) {
            let _ = writeln!(f, "{}", p.display());
        }
    }
    format!("добавлено: {} (найдено целей: {})", p.display(), bins.len() + jss.len())
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        let key = if cfg!(windows) {
            p.to_string_lossy().to_lowercase()
        } else {
            p.to_string_lossy().into_owned()
        };
        if seen.insert(key) {
            out.push(p);
        }
    }
    out
}

#[cfg(not(windows))]
fn find_bin_targets(extra: &[PathBuf]) -> Vec<PathBuf> {
    let home = home_dir();
    let mut out = vec![
        PathBuf::from("/opt/antigravity-Linux/resources/bin/language_server"),
        home.join(".gemini/bin/agy"),
        home.join(".local/bin/agy"),
    ];
    for cp in load_saved_paths().into_iter().chain(extra.iter().cloned()) {
        let (cb, _) = expand_custom_path(&cp);
        out.extend(cb);
    }
    dedup_paths(out)
}

#[cfg(not(windows))]
fn find_js_targets(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/opt/antigravity-ide-Linux/resources/app/out/main.js")];
    for cp in load_saved_paths().into_iter().chain(extra.iter().cloned()) {
        let (_, cj) = expand_custom_path(&cp);
        out.extend(cj);
    }
    dedup_paths(out)
}

#[cfg(windows)]
fn win_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "APPDATA"] {
        if let Some(val) = env::var_os(var) {
            let base = PathBuf::from(val);
            roots.push(base.join("Programs").join("Antigravity"));
            roots.push(base.join("Programs").join("Antigravity IDE"));
            roots.push(base.join("Antigravity"));
            roots.push(base.join("Antigravity IDE"));
        }
    }
    roots
}

#[cfg(windows)]
fn find_bin_targets(extra: &[PathBuf]) -> Vec<PathBuf> {
    let home = home_dir();
    let mut cands = vec![
        home.join(".gemini").join("bin").join("agy.exe"),
        home.join(".local").join("bin").join("agy.exe"),
        home.join(".gemini").join("antigravity").join("bin").join("language_server.exe"),
        home.join(".gemini").join("antigravity").join("bin").join("language_server_windows_x64.exe"),
    ];
    for root in win_roots() {
        cands.push(root.join("agy.exe"));
        for sub in [
            root.join("resources").join("bin"),
            root.join("resources").join("app").join("extensions").join("antigravity").join("bin"),
        ] {
            if let Ok(entries) = fs::read_dir(&sub) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        let lower = name.to_lowercase();
                        if lower.starts_with("language_server") && lower.ends_with(".exe") {
                            cands.push(p);
                        }
                    }
                }
            } else {
                cands.push(sub.join("language_server_windows_x64.exe"));
            }
        }
    }
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let p = dir.join("agy.exe");
            if p.is_file() {
                cands.push(p);
            }
        }
    }
    for cp in load_saved_paths().into_iter().chain(extra.iter().cloned()) {
        let (cb, _) = expand_custom_path(&cp);
        cands.extend(cb);
    }
    let unique = dedup_paths(cands);
    let existing: Vec<PathBuf> = unique.iter().filter(|p| p.is_file()).cloned().collect();
    if existing.is_empty() { unique.into_iter().take(4).collect() } else { existing }
}

#[cfg(windows)]
fn find_js_targets(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut cands: Vec<PathBuf> = win_roots()
        .into_iter()
        .map(|r| r.join("resources").join("app").join("out").join("main.js"))
        .collect();
    for cp in load_saved_paths().into_iter().chain(extra.iter().cloned()) {
        let (_, cj) = expand_custom_path(&cp);
        cands.extend(cj);
    }
    let unique = dedup_paths(cands);
    let existing: Vec<PathBuf> = unique.iter().filter(|p| p.is_file()).cloned().collect();
    if existing.is_empty() { unique.into_iter().take(2).collect() } else { existing }
}

// --- атомарная запись ------------------------------------------------------

fn is_busy_err(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
        || matches!(e.raw_os_error(), Some(5 | 26 | 32))
}

fn write_atomic(p: &Path, data: &[u8]) -> io::Result<()> {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = p.with_file_name(format!("{name}.ag-unblock.tmp"));
    let perms = fs::metadata(p).map(|m| m.permissions()).ok();
    fs::write(&tmp, data)?;
    if let Some(perm) = perms {
        let _ = fs::set_permissions(&tmp, perm);
    }
    if let Err(e) = fs::rename(&tmp, p) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// --- бинарный патч ---------------------------------------------------------

fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn replace_subslice(data: &mut [u8], old: &[u8], new: &[u8]) -> usize {
    assert_eq!(old.len(), new.len());
    let mut count = 0;
    let mut i = 0;
    while i + old.len() <= data.len() {
        if &data[i..i + old.len()] == old {
            data[i..i + old.len()].copy_from_slice(new);
            count += 1;
            i += old.len();
        } else {
            i += 1;
        }
    }
    count
}

fn patch_binary(p: &Path) -> String {
    if !p.exists() {
        return "нет файла".into();
    }
    let mut data = match fs::read(p) {
        Ok(d) => d,
        Err(e) => return format!("ошибка чтения: {e}"),
    };
    let n_old = count_subslice(&data, OLD);
    let n_new = count_subslice(&data, NEW);
    if n_new > 0 && n_old == 0 {
        return format!("уже пропатчен ({n_new} вхожд.)");
    }
    if n_old == 0 {
        return "литерал не найден - нечего патчить".into();
    }
    if let Err(e) = ensure_backup(p) {
        return format!("ошибка бэкапа: {e}");
    }
    let patched = replace_subslice(&mut data, OLD, NEW);
    match write_atomic(p, &data) {
        Ok(()) => format!("пропатчено вхождений: {patched}"),
        Err(e) if is_busy_err(&e) => "ОШИБКА: файл занят (закройте Antigravity / agy)".into(),
        Err(e) => format!("ошибка записи: {e}"),
    }
}

fn revert_file(p: &Path, label: &str) -> String {
    let b = backup_path(p);
    if !b.exists() {
        return "бэкапа нет".into();
    }
    let data = match fs::read(&b) {
        Ok(d) => d,
        Err(e) => return format!("ошибка чтения бэкапа: {e}"),
    };
    match write_atomic(p, &data) {
        Ok(()) => "откачено".into(),
        Err(e) if is_busy_err(&e) => format!("ОШИБКА: файл занят (закройте {label})"),
        Err(e) => format!("ошибка записи: {e}"),
    }
}

// --- JS-патч IDE -----------------------------------------------------------

fn brace_balance(span: &[u8]) -> isize {
    let open = span.iter().filter(|&&b| b == b'{').count() as isize;
    let close = span.iter().filter(|&&b| b == b'}').count() as isize;
    open - close
}

fn patch_js(p: &Path, skip_node: bool) -> String {
    if !p.exists() {
        return "нет файла".into();
    }
    let data = match fs::read(p) {
        Ok(d) => d,
        Err(e) => return format!("ошибка чтения: {e}"),
    };
    let re = js_regex();
    let Some(caps) = re.captures(&data) else {
        if count_subslice(&data, b"__res") > 0 {
            return "уже пропатчен".into();
        }
        return "сигнатура не найдена".into();
    };

    let m = caps.get(0).unwrap();
    let g = |i: usize| -> String {
        String::from_utf8_lossy(caps.get(i).unwrap().as_bytes()).into_owned()
    };
    let (fname, var_t, actor, ccs, ccs2) = (g(1), g(2), g(3), g(4), g(5));
    let (var_i, var_func, var_f, var_h) = (g(8), g(9), g(10), g(11));

    let payload = format!(
        "async {fname}({var_t}){{\
            this.{actor}.send({{type:{var_t}.isGcpTos?\"GCP_SIGN_IN\":\"SIGN_IN\"}});\
            this.{ccs}.resetIsTierGCPTos();\
            try{{\
                try{{ await this.{ccs2}.loadCodeAssist({var_t}); }}catch(_){{}}\
                try{{ await this.{ccs2}.onboardUser(\"standard-tier\",{var_t}); }}\
                catch(_){{ try{{ await this.{ccs2}.onboardUser(\"free-tier\",{var_t}); }}catch(__){{}} }}\
                let __res={{settings:{{}},userTier:{{id:\"pro\",description:\"Pro\"}}}};\
                try{{ const __s=await this.refreshUserStatus({var_t});\
                if(__s&&__s.settings) __res.settings=__s.settings; }}catch(_){{}}\
                const {var_i}={var_func}({var_t});\
                try{{ this.{var_f}.pushUpdate({var_i}); }}catch(_){{}}\
                this.{actor}.send({{type:\"AUTH_SUCCESS\",tokenInfo:{var_t}}});\
                this.{var_h}.fire({{settings:__res.settings,userTier:__res.userTier}});\
            }}catch(e){{}}\
            return;"
    );

    let old_span = &data[m.start()..m.end()];
    if brace_balance(old_span) != brace_balance(payload.as_bytes()) {
        return "ОТКАЗ: баланс скобок не совпадает, файл не тронут".into();
    }

    let mut patched = Vec::with_capacity(data.len() - old_span.len() + payload.len());
    patched.extend_from_slice(&data[..m.start()]);
    patched.extend_from_slice(payload.as_bytes());
    patched.extend_from_slice(&data[m.end()..]);

    if !skip_node {
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("main");
        let tmp = p.with_file_name(format!("{stem}.ag-unblock-check.js"));
        if let Err(e) = fs::write(&tmp, &patched) {
            return format!("ошибка записи temp-файла: {e}");
        }
        let res = Command::new("node").arg("--check").arg(&tmp).output();
        let _ = fs::remove_file(&tmp);
        match res {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return "node не найден - запись пропущена (запустите с --no-node для обхода проверки)".into();
            }
            Err(e) => return format!("ошибка запуска node: {e}"),
            Ok(out) if !out.status.success() => {
                return "ОТКАЗ: синтаксис не проходит проверку, файл не тронут".into();
            }
            Ok(_) => {}
        }
    }

    if let Err(e) = ensure_backup(p) {
        return format!("ошибка бэкапа: {e}");
    }
    match write_atomic(p, &patched) {
        Ok(()) => "пропатчено: auth-flow".into(),
        Err(e) if is_busy_err(&e) => "ОШИБКА: файл занят (закройте Antigravity IDE)".into(),
        Err(e) => format!("ошибка записи: {e}"),
    }
}

// --- сеть (системный DNS + rustls + HTTP-проба) ----------------------------

fn resolve_v4(host: &str) -> Vec<Ipv4Addr> {
    let Ok(addrs) = (host, 443u16).to_socket_addrs() else {
        return Vec::new();
    };
    let mut ips = Vec::new();
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            if !ips.contains(&v4) {
                ips.push(v4);
            }
        }
    }
    ips
}

fn resolve_v6(host: &str) -> Vec<Ipv6Addr> {
    let Ok(addrs) = (host, 443u16).to_socket_addrs() else {
        return Vec::new();
    };
    let mut ips = Vec::new();
    for addr in addrs {
        if let IpAddr::V6(v6) = addr.ip() {
            if !ips.contains(&v6) {
                ips.push(v6);
            }
        }
    }
    ips
}

fn is_direct_google_ip(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    matches!((a, b), (172, 217) | (142, 250) | (142, 251) | (216, 58))
}

fn is_blocked_country(c: &str) -> bool {
    matches!(c.trim().to_uppercase().as_str(), "RU" | "BY" | "RUSSIA" | "BELARUS")
}

fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn connect_tls_ip(host: &str, ip: IpAddr, timeout_s: u64, cfg: Arc<ClientConfig>) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let addr = SocketAddr::new(ip, 443);
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_s))
        .map_err(|e| format!("TCP: {e}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
    let sni = ServerName::try_from(host.to_string()).map_err(|e| format!("SNI: {e}"))?;
    let mut conn = ClientConnection::new(cfg, sni).map_err(|e| format!("TLS init: {e}"))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).map_err(|e| format!("TLS handshake: {e}"))?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

fn connect_tls(host: &str, ip: Ipv4Addr, cfg: Arc<ClientConfig>) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    connect_tls_ip(host, IpAddr::V4(ip), 8, cfg)
}

fn https_get(host: &str, ip: IpAddr, path: &str, extra_headers: &str, cfg: Arc<ClientConfig>) -> Result<String, String> {
    let mut stream = connect_tls_ip(host, ip, 5, cfg)?;
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Accept-Encoding: identity\r\n\
         {extra_headers}\
         Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    if let Err(e) = stream.read_to_end(&mut buf) {
        if buf.is_empty() {
            return Err(format!("read: {e}"));
        }
    }
    let raw = String::from_utf8_lossy(&buf);
    Ok(raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| raw.into_owned()))
}

struct CfTrace {
    ip: String,
    loc: String,
    colo: String,
}

fn cf_trace(ipv6: bool, cfg: Arc<ClientConfig>) -> Option<CfTrace> {
    let ip: IpAddr = if ipv6 {
        IpAddr::V6(*resolve_v6("www.cloudflare.com").first()?)
    } else {
        IpAddr::V4(*resolve_v4("www.cloudflare.com").first()?)
    };
    let body = https_get("www.cloudflare.com", ip, "/cdn-cgi/trace", "", cfg).ok()?;
    let (mut out_ip, mut loc, mut colo) = (String::new(), String::new(), String::new());
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "ip" => out_ip = v.trim().to_string(),
                "loc" => loc = v.trim().to_string(),
                "colo" => colo = v.trim().to_string(),
                _ => {}
            }
        }
    }
    if out_ip.is_empty() { None } else { Some(CfTrace { ip: out_ip, loc, colo }) }
}

fn google_geo_country(cfg: Arc<ClientConfig>) -> Option<String> {
    if let Some(&ip) = resolve_v4("policies.google.com").first() {
        if let Ok(html) = https_get("policies.google.com", IpAddr::V4(ip), "/terms?hl=en", "", cfg.clone()) {
            let re = RegexBuilder::new(r"Country version:</a>\s*([^<\n]+)")
                .unicode(false)
                .build()
                .ok()?;
            if let Some(caps) = re.captures(html.as_bytes()) {
                let s = String::from_utf8_lossy(caps.get(1)?.as_bytes()).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    if let Some(&ip) = resolve_v4("www.youtube.com").first() {
        if let Ok(html) = https_get("www.youtube.com", IpAddr::V4(ip), "/?hl=en", "Cookie: SOCS=CAI\r\n", cfg) {
            let re = RegexBuilder::new(r#""countryCode":"([A-Z]{2})""#)
                .unicode(false)
                .build()
                .ok()?;
            if let Some(caps) = re.captures(html.as_bytes()) {
                return Some(String::from_utf8_lossy(caps.get(1)?.as_bytes()).into_owned());
            }
        }
    }
    None
}

fn cert_info(host: &str, ip: Ipv4Addr, cfg: Arc<ClientConfig>) -> String {
    match connect_tls(host, ip, cfg) {
        Err(e) => format!("ошибка TLS: {e}"),
        Ok(stream) => {
            let Some(certs) = stream.conn.peer_certificates() else {
                return "ошибка TLS: нет сертификата".into();
            };
            let Some(leaf) = certs.first() else {
                return "ошибка TLS: пустая цепочка".into();
            };
            match parse_x509_certificate(leaf.as_ref()) {
                Ok((_, x509)) => format!("{} / {}", x509.issuer(), x509.subject()),
                Err(e) => format!("ошибка X509: {e}"),
            }
        }
    }
}

fn probe_gate(host: &str, ip: Ipv4Addr, cfg: Arc<ClientConfig>) -> Result<String, String> {
    let mut stream = connect_tls(host, ip, cfg)?;
    let body = r#"{"metadata":{"pluginType":"ANTIGRAVITY","ideType":"IDE"}}"#;
    let req = format!(
        "POST /v1internal:loadCodeAssist HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Bearer probe\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    let mut buf = Vec::new();
    if let Err(e) = stream.read_to_end(&mut buf) {
        if buf.is_empty() {
            return Err(format!("read: {e}"));
        }
    }
    let raw = String::from_utf8_lossy(&buf);
    Ok(raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| raw.into_owned()))
}

// --- команды ---------------------------------------------------------------

fn cmd_status(extra: &[PathBuf]) -> ExitCode {
    println!("=== Клиентский гейт: патч ineligible -> inexeligible ===");
    for p in find_bin_targets(extra) {
        println!("  {}", p.display());
        if !p.exists() {
            println!("      нет файла");
            continue;
        }
        match fs::read(&p) {
            Ok(d) => {
                let n_old = count_subslice(&d, OLD);
                let n_new = count_subslice(&d, NEW);
                let st = if n_new > 0 && n_old == 0 { "ПРОПАТЧЕН" } else { "НЕ ПРОПАТЧЕН" };
                println!("      ineligible={n_old}  inexeligible={n_new}  -> {st}");
            }
            Err(e) => println!("      ошибка чтения: {e}"),
        }
    }

    println!("\n=== IDE: JS-обработчик отказа ===");
    let re = js_regex();
    for p in find_js_targets(extra) {
        println!("  {}", p.display());
        if !p.exists() {
            println!("      нет файла");
            continue;
        }
        match fs::read(&p) {
            Ok(d) => {
                let patched = !re.is_match(&d) && count_subslice(&d, b"__res") > 0;
                println!("      -> {}", if patched { "ПРОПАТЧЕН" } else { "НЕ ПРОПАТЧЕН" });
            }
            Err(e) => println!("      ошибка чтения: {e}"),
        }
    }

    println!("\n=== Сеть: DNS-подмена gate-хостов (системный резолвер) ===");
    for &h in GATE_HOSTS.iter().chain(std::iter::once(&AUTH_HOST)) {
        let ips: Vec<String> = resolve_v4(h).into_iter().map(|ip| ip.to_string()).collect();
        let line = if ips.is_empty() { "НЕ РАЗРЕШАЕТСЯ".into() } else { ips.join(", ") };
        println!("  {h}\n      {line}");
    }
    ExitCode::SUCCESS
}

fn cmd_apply(skip_node: bool, extra: &[PathBuf]) -> ExitCode {
    println!("=== Бинари ===");
    for p in find_bin_targets(extra) {
        println!("  {}: {}", p.display(), patch_binary(&p));
    }
    println!("\n=== IDE JS ===");
    for p in find_js_targets(extra) {
        println!("  {}: {}", p.display(), patch_js(&p, skip_node));
    }
    println!("\nБэкапы: {}", backup_dir().display());
    println!("Перезапустите Antigravity / Antigravity IDE.");
    ExitCode::SUCCESS
}

fn cmd_revert(extra: &[PathBuf]) -> ExitCode {
    for p in find_bin_targets(extra) {
        println!("  {}: {}", p.display(), revert_file(&p, "Antigravity / agy"));
    }
    for p in find_js_targets(extra) {
        println!("  {}: {}", p.display(), revert_file(&p, "Antigravity IDE"));
    }
    ExitCode::SUCCESS
}

fn cmd_verify() -> ExitCode {
    let mut ok = true;
    let mut daily_ip: Option<Ipv4Addr> = None;
    let cfg = tls_config();
    println!("=== DNS-подмена + TLS ===");
    for &h in GATE_HOSTS.iter().chain(std::iter::once(&AUTH_HOST)) {
        let ips = resolve_v4(h);
        let Some(&ip) = ips.first() else {
            println!("  {h}: НЕ РАЗРЕШАЕТСЯ");
            ok = false;
            continue;
        };
        if h == "daily-cloudcode-pa.googleapis.com" {
            daily_ip = Some(ip);
        }
        if ip.is_loopback() {
            println!("  {h}\n      {ip}\n      ВНИМАНИЕ: локальный редирект (остатки AG Unlocker / NRPT / hosts)");
            ok = false;
            continue;
        }
        let info = cert_info(h, ip, cfg.clone());
        println!("  {h}\n      {ip}\n      сертификат: {info}");
        if !info.contains("Google") {
            println!("      ВНИМАНИЕ: сертификат не Google");
            let lower = info.to_lowercase();
            if lower.contains("10060") || lower.contains("timed out") || lower.contains("timeout") {
                println!("      ПОДСКАЗКА: таймаут TLS handshake — проверьте TUN/MTU (в Happ: Sing-box вместо Xray TUN) или DPI/корп. VPN");
            }
            ok = false;
        }
    }

    println!("\n=== Внешний IP и геолокация Google ===");
    let cf4 = cf_trace(false, cfg.clone());
    let cf6 = cf_trace(true, cfg.clone());
    let loc4 = cf4.as_ref().map(|c| c.loc.as_str()).unwrap_or("");
    let loc6 = cf6.as_ref().map(|c| c.loc.as_str()).unwrap_or("");
    match &cf4 {
        Some(c) => println!("  IPv4 (Cloudflare): {}  loc={}  colo={}", c.ip, c.loc, c.colo),
        None => println!("  IPv4 (Cloudflare): недоступен"),
    }
    match &cf6 {
        Some(c) => println!("  IPv6 (Cloudflare): {}  loc={}  colo={}", c.ip, c.loc, c.colo),
        None => println!("  IPv6 (Cloudflare): нет / не используется"),
    }

    let g_country = google_geo_country(cfg.clone());
    match &g_country {
        Some(c) => println!("  Геолокация Google: {c}"),
        None => println!("  Геолокация Google: не удалось определить"),
    }

    if let Some(ip) = daily_ip {
        if is_direct_google_ip(ip) && is_blocked_country(loc4) {
            println!("  ВНИМАНИЕ: нет ни VPN, ни DNS-подмены — трафик идёт напрямую из {loc4}");
            ok = false;
        }
    }
    if !loc4.is_empty() && !is_blocked_country(loc4) && is_blocked_country(loc6) {
        println!("  ВНИМАНИЕ: утечка IPv6 мимо VPN ({loc6})");
        ok = false;
    }
    if let Some(gc) = &g_country {
        if is_blocked_country(gc) && !loc4.is_empty() && !is_blocked_country(loc4) {
            println!("  ВНИМАНИЕ: Google считает ваш VPN-сервер российским ({gc}) — смените сервер/локацию или используйте DNS-подмену");
            ok = false;
        }
    }

    println!("\n=== Ответ сервера (401 = запрос дошёл до Google) ===");
    let h = "daily-cloudcode-pa.googleapis.com";
    if let Some(ip) = daily_ip.filter(|ip| !ip.is_loopback()) {
        match probe_gate(h, ip, cfg) {
            Ok(resp) => {
                let preview: String = resp.chars().take(220).collect();
                println!("  {h}: {preview}");
                if !resp.contains("UNAUTHENTICATED") && !resp.contains("\"code\": 401") {
                    println!("      ВНИМАНИЕ: не 401");
                    ok = false;
                }
            }
            Err(e) => {
                println!("  {h}: ошибка запроса: {e}");
                ok = false;
            }
        }
    }
    println!("\nИтог: {}", if ok { "ОК" } else { "есть проблемы" });
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

#[cfg(windows)]
fn enable_utf8_console() {
    extern "system" {
        fn SetConsoleOutputCP(code_page_id: u32) -> i32;
        fn SetConsoleCP(code_page_id: u32) -> i32;
    }
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }
}

#[cfg(not(windows))]
fn enable_utf8_console() {}

fn open_url(url: &str) {
    println!("Чат поддержки: {url}");
    #[cfg(windows)]
    let res = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(not(windows))]
    let res = Command::new("xdg-open").arg(url).spawn();
    if let Err(e) = res {
        println!("Не удалось открыть браузер автоматически ({e}). Скопируйте ссылку выше вручную.");
    }
}

fn run_menu() -> ExitCode {
    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        println!("\n=== ag-unblock ===");
        println!("Чат поддержки: {SUPPORT_URL}");
        println!("  1. Статус (файлы и DNS)");
        println!("  2. Применить патч (apply)");
        println!("  3. Применить патч без проверки Node.js (apply --no-node)");
        println!("  4. Откатить патч (revert)");
        println!("  5. Проверить сеть и сертификаты (verify)");
        println!("  6. Открыть чат поддержки (Telegram)");
        println!("  7. Добавить папку/файл вручную");
        println!("  0. Выход");
        print!("\nВыберите действие [0-7]: ");
        let _ = io::stdout().flush();

        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }

        println!();
        match line.trim() {
            "1" => { let _ = cmd_status(&[]); }
            "2" => { let _ = cmd_apply(false, &[]); }
            "3" => { let _ = cmd_apply(true, &[]); }
            "4" => { let _ = cmd_revert(&[]); }
            "5" => { let _ = cmd_verify(); }
            "6" => { open_url(SUPPORT_URL); }
            "7" => {
                print!("Введите путь к папке установки или файлу: ");
                let _ = io::stdout().flush();
                let mut raw = String::new();
                if stdin.read_line(&mut raw).is_ok() && !raw.trim().is_empty() {
                    println!("{}", save_custom_path(&raw));
                }
            }
            "0" | "q" | "exit" => break,
            _ => {
                println!("Неизвестный пункт. Введите цифру от 0 до 7.");
                continue;
            }
        }

        print!("\nНажмите Enter, чтобы вернуться в меню...");
        let _ = io::stdout().flush();
        line.clear();
        if matches!(stdin.read_line(&mut line), Ok(0) | Err(_)) {
            break;
        }
    }
    ExitCode::SUCCESS
}

fn parse_extra_paths(args: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--path" && i + 1 < args.len() {
            out.push(clean_path(&args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn main() -> ExitCode {
    enable_utf8_console();
    let args: Vec<String> = env::args().skip(1).collect();
    let extra = if args.len() > 1 { parse_extra_paths(&args[1..]) } else { Vec::new() };
    match args.first().map(String::as_str) {
        None => run_menu(),
        Some("status") => cmd_status(&extra),
        Some("apply") => cmd_apply(args[1..].iter().any(|a| a == "--no-node"), &extra),
        Some("revert") => cmd_revert(&extra),
        Some("verify") => cmd_verify(),
        Some("add-path") if args.len() >= 2 => {
            println!("{}", save_custom_path(&args[1]));
            ExitCode::SUCCESS
        }
        Some("support") => {
            open_url(SUPPORT_URL);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Использование: ag-unblock [status | apply [--no-node] | revert | verify | add-path <путь> | support] [--path <путь>]");
            ExitCode::from(2)
        }
    }
}
