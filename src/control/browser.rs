use anyhow::{Context, Result};
use std::process::{Command, Stdio};

pub struct AutoCookieCapture;

impl AutoCookieCapture {
    pub fn find_python() -> Option<String> {
        for candidate in &["python3", "python", "py"] {
            if Command::new(candidate)
                .args(["-c", "import sys; sys.exit(0)"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some(candidate.to_string());
            }
        }
        None
    }

    pub fn is_available() -> bool {
        let py_cmd = match Self::find_python() {
            Some(p) => p,
            None => return false,
        };

        let ws_ok = Command::new(&py_cmd)
            .args(["-c", "import websockets"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let browser_ok = Self::detect_browser().is_some();
        ws_ok && browser_ok
    }

    pub fn detect_browser() -> Option<(String, Vec<String>)> {
        // 1. Windows standard paths & registry/PATH lookups
        #[cfg(target_os = "windows")]
        {
            let mut candidates = Vec::new();
            if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
                candidates.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", pf86));
                candidates.push(format!(r"{}\Google\Chrome\Application\chrome.exe", pf86));
            }
            if let Ok(pf) = std::env::var("ProgramFiles") {
                candidates.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", pf));
                candidates.push(format!(r"{}\Google\Chrome\Application\chrome.exe", pf));
                candidates.push(format!(r"{}\BraveSoftware\Brave-Browser\Application\brave.exe", pf));
            }
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                candidates.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", local));
                candidates.push(format!(r"{}\Google\Chrome\Application\chrome.exe", local));
                candidates.push(format!(r"{}\BraveSoftware\Brave-Browser\Application\brave.exe", local));
            }

            for path in candidates {
                if std::path::Path::new(&path).exists() {
                    return Some((path, vec![]));
                }
            }

            for c in &["msedge.exe", "chrome.exe", "brave.exe"] {
                if Command::new("where")
                    .arg(c)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    return Some((c.to_string(), vec![]));
                }
            }
        }

        // 2. Linux via Flatpak
        #[cfg(target_os = "linux")]
        if Command::new("flatpak")
            .args(["info", "com.brave.Browser"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some((
                "flatpak".to_string(),
                vec!["run".to_string(), "com.brave.Browser".to_string()],
            ));
        }

        // 3. Linux native browsers
        let candidates = [
            "google-chrome-stable",
            "google-chrome",
            "chromium-browser",
            "chromium",
            "brave-browser",
            "brave",
            "microsoft-edge",
        ];

        for c in candidates {
            if Command::new("which")
                .arg(c)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some((c.to_string(), vec![]));
            }
        }

        None
    }

    pub async fn capture(url: &str) -> Result<Option<String>> {
        let (prog, base_args) = match Self::detect_browser() {
            Some(b) => b,
            None => return Ok(None),
        };

        let py_cmd = match Self::find_python() {
            Some(p) => p,
            None => return Ok(None),
        };

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(9338);
        let temp_dir = std::env::temp_dir();
        let user_data_dir = temp_dir.join(format!("open_cisco_zta_enroll_{}", std::process::id()));

        let mut browser_cmd = Command::new(&prog);
        for a in &base_args {
            browser_cmd.arg(a);
        }
        browser_cmd
            .arg(format!("--user-data-dir={}", user_data_dir.display()))
            .arg(format!("--remote-debugging-port={}", port))
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = browser_cmd
            .spawn()
            .with_context(|| format!("Failed to spawn browser {:?}", prog))?;

        let helper_script = r#"
import sys, json, time, urllib.request, asyncio, websockets

async def grab_cookie(port, timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=1)
            tabs = json.loads(req.read().decode())
            for tab in tabs:
                ws_url = tab.get("webSocketDebuggerUrl")
                if not ws_url: continue
                async with websockets.connect(ws_url) as ws:
                    await ws.send(json.dumps({
                        "id": 1,
                        "method": "Network.getCookies",
                        "params": {"urls": ["https://enroll-ui.ztna.sse.cisco.com", "https://enroll.ztna.sse.cisco.com"]}
                    }))
                    resp = json.loads(await ws.recv())
                    cookies = resp.get("result", {}).get("cookies", [])
                    for c in cookies:
                        if c.get("name") == "elb-sso-jwt" and c.get("value"):
                            print(c["value"])
                            return
        except Exception:
            pass
        await asyncio.sleep(1)

asyncio.run(grab_cookie(int(sys.argv[1])))
"#;

        let py_cmd_clone = py_cmd.clone();
        let py_join = tokio::task::spawn_blocking(move || {
            Command::new(&py_cmd_clone)
                .args(["-c", helper_script, &port.to_string()])
                .output()
        })
        .await;

        // Cleanup browser & profile dir regardless of join result
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&user_data_dir);

        let py_output = py_join?;

        if let Ok(out) = py_output {
            let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !token.is_empty() {
                return Ok(Some(token));
            }
        }

        Ok(None)
    }
}
