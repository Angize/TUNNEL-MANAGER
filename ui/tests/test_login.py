"""Browser tests against the built UI and the panel's login and session handlers."""

import importlib.util
import os
import secrets
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright


UI = Path(__file__).resolve().parents[1]


class PanelLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("panel", UI.parent / "tnl-central.py")
        panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(panel)
        panel.UI_DIR = str(Path(os.environ.get("TNL_TEST_DIST", UI / "dist")))
        cls.username = "اپراتور"
        cls.password = " " + secrets.token_hex(12) + " "
        salt, digest = panel.hash_password(cls.password)
        events = patch.object(panel, "log_event")
        events.start()
        cls.addClassCleanup(events.stop)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        cls.server.conf = {"user": cls.username, "salt": salt, "hash": digest, "secret": secrets.token_hex(32)}
        thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(cls.server.shutdown)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}/"
        runtime = sync_playwright().start()
        cls.addClassCleanup(runtime.stop)
        cls.browser = runtime.chromium.launch(executable_path=os.environ.get("TNL_TEST_CHROMIUM"))
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.page = self.browser.new_page(viewport={"width": 375, "height": 812}, reduced_motion="reduce")
        self.addCleanup(self.page.close)
        # Only the login, session and static asset routes are under test.
        self.page.route("**/api/**", lambda route: route.continue_() if route.request.url.endswith("/api/login")
                        else route.fulfill(status=503, json={"error": "دادهٔ آزمایشی در دسترس نیست"}))
        self.page.goto(self.origin)
        self.user = self.page.get_by_label("نام کاربری", exact=True)
        self.password_field = self.page.get_by_label("رمز عبور", exact=True)

    def test_mobile_taps_and_autofill_preserve_the_login_surfaces(self):
        with self.browser.new_context(viewport={"width": 393, "height": 851}, has_touch=True,
                                      is_mobile=True, reduced_motion="reduce") as context:
            page = context.new_page()
            page.goto(self.origin)
            page.evaluate("document.fonts.ready")
            devtools = context.new_cdp_session(page)
            devtools.send("DOM.enable")
            devtools.send("CSS.enable")
            root = devtools.send("DOM.getDocument")["root"]["nodeId"]
            for theme in ("light", "dark"):
                if theme == "dark":
                    page.locator("#themeControl").tap()
                    page.locator("#edit").tap()
                for name in ("username", "password"):
                    field = page.locator("#" + name)
                    field.fill("123456")
                    node = devtools.send("DOM.querySelector", {"nodeId": root, "selector": "#" + name})["nodeId"]
                    bounds = field.bounding_box()
                    # Sample the empty part of the input, away from the text and caret.
                    sample = {"x": int(bounds["x"]) + 8, "y": int(bounds["y"]) + 20, "width": 16, "height": 12}
                    ordinary = page.screenshot(clip=sample)
                    devtools.send("CSS.forcePseudoState", {"nodeId": node, "forcedPseudoClasses": ["autofill"]})
                    self.assertTrue(field.evaluate("el => el.matches(':autofill')"))
                    self.assertEqual(page.screenshot(clip=sample), ordinary)
                    devtools.send("CSS.forcePseudoState", {"nodeId": node, "forcedPseudoClasses": []})
                    if name == "username":
                        page.get_by_role("button", name="ادامه").tap()
                for selector in ("#themeControl", "#motionControl", "#eye", "#password", "#action"):
                    color = page.locator(selector).evaluate("el => getComputedStyle(el).webkitTapHighlightColor")
                    self.assertEqual(color, "rgba(0, 0, 0, 0)")
                page.locator("#eye").tap()
                expect(page.locator("#password")).to_have_attribute("type", "text")
                page.get_by_role("button", name="ورود به پنل").tap()
                expect(page.get_by_role("alert")).to_have_text("نام کاربری یا رمز اشتباه است")
                expect(page.locator("#action")).to_have_css("filter", "none")

    def test_retry_after_rejection_and_open_authenticated_dashboard_in_selected_theme(self):
        sent = []
        self.page.on("request", lambda req: sent.append(req.post_data_json) if req.url.endswith("/api/login") else None)
        expect(self.page.locator(".brand")).to_have_text("گره‌چین")
        self.page.get_by_role("button", name="نمایش تم تیره").click()
        self.page.reload()
        expect(self.page.locator("html")).to_have_class("dark")
        self.page.get_by_role("button", name="ادامه").click()
        expect(self.user).to_be_focused()
        self.user.fill("اشتباه")
        self.user.press("Enter")
        self.password_field.fill("discard")
        self.page.get_by_role("button", name="تغییر حساب").click()
        self.user.fill(self.username)
        self.user.press("Enter")
        expect(self.password_field).to_be_empty()
        expect(self.password_field).to_be_focused()
        self.password_field.press("Enter")
        expect(self.page.get_by_role("alert")).to_have_text("رمز عبور را وارد کنید.")
        self.assertEqual(sent, [])
        self.password_field.fill("wrong")
        self.page.get_by_role("button", name="نمایش رمز عبور").click()
        expect(self.password_field).to_have_attribute("type", "text")
        self.page.get_by_role("button", name="پنهان کردن رمز عبور").click()
        self.password_field.press("Enter")
        expect(self.page.get_by_role("alert")).to_have_text("نام کاربری یا رمز اشتباه است")
        self.password_field.fill(self.password)
        with self.page.expect_response(lambda r: r.url == self.origin and r.request.is_navigation_request()) as target:
            self.password_field.press("Enter")
            self.page.evaluate("document.getElementById('login')?.requestSubmit()")
        self.assertEqual(target.value.status, 200)
        expect(self.page.locator("#root")).to_be_attached()
        expect(self.page.locator("html")).to_have_class("dark")
        self.assertTrue(any(c["name"] == "tnl_session" and c["httpOnly"] for c in self.page.context.cookies()))
        self.assertEqual(sent, [{"user": self.username, "pass": "wrong"}, {"user": self.username, "pass": self.password}])

    def test_password_glyph_matches_field_icon_and_keeps_its_touch_target(self):
        self.user.fill(self.username)
        self.user.press("Enter")
        self.password_field.fill("نمونه")
        field_icon = self.page.locator("#passBox .field-glyph svg").bounding_box()
        for width in (393, 1280):
            self.page.set_viewport_size({"width": width, "height": 812})
            for name, pressed in (("نمایش رمز عبور", "false"), ("پنهان کردن رمز عبور", "true")):
                toggle = self.page.get_by_role("button", name=name)
                expect(toggle).to_have_attribute("aria-pressed", pressed)
                glyph = toggle.locator("svg").bounding_box()
                target = toggle.bounding_box()
                for dimension in ("width", "height"):
                    self.assertEqual(glyph[dimension], field_icon[dimension])
                    self.assertGreaterEqual(target[dimension], 44)
                toggle.click()
                expect(self.password_field).to_have_value("نمونه")
                expect(self.password_field).to_have_attribute("type", "text" if pressed == "false" else "password")

    def test_recover_from_network_error_and_show_server_wait_message(self):
        self.user.fill(self.username)
        self.user.press("Enter")
        self.password_field.fill("unused")
        self.page.route("**/api/login", lambda route: route.abort())
        self.password_field.press("Enter")
        expect(self.page.get_by_role("alert")).to_contain_text("ارتباط با پنل برقرار نشد")
        self.page.unroute("**/api/login")
        message = "تلاشِ زیاد — چند دقیقه صبر کن"
        self.page.route("**/api/login", lambda route: route.fulfill(status=429, json={"error": message}))
        self.password_field.press("Enter")
        expect(self.page.get_by_role("alert")).to_have_text(message)
        expect(self.page.get_by_role("button", name="ورود به پنل")).to_be_enabled()


if __name__ == "__main__":
    unittest.main()
