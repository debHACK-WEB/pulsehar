from pathlib import Path
from playwright.sync_api import sync_playwright


def capture_har_from_url(
    target_url: str,
    output_har: str | Path,
    wait_seconds: int = 8,
    headless: bool = False,
    interactive_pause: bool = False,
    browser_name: str = "firefox",
    executable_path: str | None = None,
) -> Path:
    out_path = Path(output_har)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        launcher = getattr(p, browser_name, None)
        if launcher is None:
            raise ValueError(f"Unsupported browser: {browser_name}")

        launch_kwargs = {"headless": headless}
        if executable_path:
            launch_kwargs["executable_path"] = executable_path

        browser = launcher.launch(**launch_kwargs)
        context = browser.new_context(
            record_har_path=str(out_path),
            record_har_content="embed",
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.goto(target_url, wait_until="domcontentloaded", timeout=30000)

        if interactive_pause:
            input("\n  [!] Browser ready. Interact with the allowed target, then press Enter to save HAR...")
        elif wait_seconds > 0:
            page.wait_for_timeout(wait_seconds * 1000)

        context.close()
        browser.close()

    return out_path
