"""Run after npm run build with Python Playwright, Chromium and the panel's Python dependencies."""

import mimetypes
import os
import runpy
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


UI = Path(__file__).resolve().parents[1]
DIST = Path(os.environ.get("TNL_TEST_DIST", UI / "dist"))
ORIGIN = "http://panel.test/"


class ResponsivePanel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        panel = runpy.run_path(str(UI.parent / "tnl-central.py"))
        config = panel["api_ui_config"]({})
        nodes = [
            {"id": str(i), "name": f"node-{i}", "host": f"192.0.2.{i}", "online": False,
             "uptime": [100] * config["uptime_cells"], "uptime_pct": 100}
            for i in range(1, 7)
        ]
        cls.data = {
            "ui-config": config,
            "summary": {"nodes_total": len(nodes), "ev_seq": "0-0", "ui_interval": 30},
            "readiness": {"ok": True},
            "acts": {"acts": []},
            "nodes": {"nodes": nodes, "uptime_window": 24},
            "node-names": {"nodes": [
                {**node, "name": "long-datacenter-" + "q" * 36 + node["id"], "online": True}
                for node in nodes
            ]},
            "fleet": {"links": [], "total": 0},
            "portfw-list": {"portfw": [], "total": 0},
            "proxies": {"proxies": []},
            "settings": {**panel["settings_full"]({}), "tuning": config["tuning_defaults"]},
            "agent-info": {"none": True, "delivery": "push"},
            "core-versions": {"versions": [], "missing": [], "delivery": "push"},
            "push-status": {"idle": True, "done": True},
            "cdn": {"cdn": {"cf": {}, "ar": {}, "hosts": [], "edges": [], "fronts": []}},
            "cdn-edge": {"ok": True, "edges": []},
        }
        cls.runtime = sync_playwright().start()
        cls.addClassCleanup(cls.runtime.stop)
        cls.browser = cls.runtime.chromium.launch(executable_path=os.environ.get("TNL_TEST_CHROMIUM"))
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.page = self.browser.new_page(reduced_motion="reduce")
        self.addCleanup(self.page.close)
        self.page.route(ORIGIN + "**", self.serve)
        self.page.goto(ORIGIN)
        expect(self.page.locator(".gauges")).to_be_visible()
        self.page.evaluate("document.fonts.ready")

    def serve(self, route):
        path = urlsplit(route.request.url).path
        if path.startswith("/api/"):
            name = path[5:]
            if name in self.data:
                route.fulfill(json=self.data[name])
            else:
                route.fulfill(status=404, json={"error": name})
            return
        file = DIST / (path.lstrip("/") or "index.html")
        route.fulfill(path=file, content_type=mimetypes.guess_type(file)[0])

    def resize(self, width, height):
        self.page.set_viewport_size({"width": width, "height": height})

    def card_boxes(self, cards):
        return cards.evaluate_all("""async cards => {
            const bodies = cards.flatMap(card => [...card.querySelectorAll('.cbody, .cbody-in')])
            await Promise.all(bodies.flatMap(el => el.getAnimations().map(animation => animation.finished)))
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(resolve, 0))))
            return cards.map(c => [c.offsetLeft, c.offsetTop, c.offsetWidth, c.offsetHeight])
        }""")

    def test_resource_dials_fit_inside_phone_cards(self):
        self.resize(320, 568)
        gauges = self.page.locator(".gauge")
        expect(gauges).to_have_count(3)
        card = self.page.locator(".ocentral").bounding_box()
        for element in gauges.all():
            gauge = element.bounding_box()
            bounds = element.locator("svg").bounding_box()
            self.assertGreaterEqual(bounds["x"], max(card["x"], gauge["x"]))
            self.assertLessEqual(bounds["x"] + bounds["width"], gauge["x"] + gauge["width"] + 1)
            self.assertLessEqual(gauge["x"] + gauge["width"], card["x"] + card["width"])

    def test_touch_controls_and_autofilled_fields_in_node_form(self):
        with self.browser.new_context(viewport={"width": 393, "height": 851}, has_touch=True,
                                      is_mobile=True, reduced_motion="reduce") as context:
            page = context.new_page()
            page.route(ORIGIN + "**", self.serve)
            page.goto(ORIGIN)
            expect(page.locator(".gauges")).to_be_visible()
            devtools = context.new_cdp_session(page)
            devtools.send("DOM.enable")
            devtools.send("CSS.enable")
            root = devtools.send("DOM.getDocument")["root"]["nodeId"]

            def force(selector, states):
                node = devtools.send("DOM.querySelector", {"nodeId": root, "selector": selector})["nodeId"]
                devtools.send("CSS.forcePseudoState", {"nodeId": node, "forcedPseudoClasses": states})

            def check_autofill(selector):
                field = page.locator(selector).first
                field.fill("sample")
                for focused in (True, False):
                    with self.subTest(theme=theme, field=selector, focused=focused):
                        if not focused:
                            field.blur()
                        field.scroll_into_view_if_needed()
                        bounds = field.bounding_box()
                        sample = {"x": int(bounds["x"] + bounds["width"] / 2),
                                  "y": int(bounds["y"] + bounds["height"] / 3), "width": 8, "height": 6}
                        ordinary = page.screenshot(clip=sample, caret="hide")
                        force(selector, ["autofill"])
                        try:
                            self.assertTrue(field.evaluate("el => el.matches(':autofill')"))
                            self.assertEqual(ordinary, page.screenshot(clip=sample, caret="hide"))
                            expect(field).to_have_value("sample")
                        finally:
                            force(selector, [])
                field.fill("")
                field.blur()

            page.locator(".tabbar button").nth(1).tap()
            for theme in ("light", "dark"):
                if theme == "dark":
                    page.locator(".mtop button").last.tap()
                    expect(page.locator("html")).to_have_class("dark")
                check_autofill(".lpane:not([inert]) input.search")
                page.keyboard.press("Control+k")
                check_autofill(".palin input")
                page.locator(".palin input").press("Escape")
                page.locator(".lpane:not([inert]) .tbtnrow button").first.tap()
                modal = page.get_by_role("dialog")
                expect(modal).to_be_visible()
                close = ".modal .mx"
                original = page.locator(close).evaluate("el => getComputedStyle(el).backgroundColor")
                force(close, ["hover"])
                expect(page.locator(close)).to_have_css("background-color", original)
                expect(page.locator(close)).to_have_css("-webkit-tap-highlight-color", "rgba(0, 0, 0, 0)")
                force(close, [])
                for selector in ('.modal input[placeholder="DE02"]', '.modal .authbox input[type="password"]',
                                 '.modal .authbox textarea', '.modal textarea.blist'):
                    if selector.endswith(".blist"):
                        modal.locator(".seg").first.get_by_role("radio").nth(1).tap()
                    elif selector.endswith("textarea"):
                        modal.locator(".authseg button").nth(1).tap()
                    check_autofill(selector)
                page.locator(close).tap()
                expect(modal).to_have_count(0)

    def test_fleet_reflows_and_keeps_the_form_footer_reachable(self):
        self.page.locator(".nav .navi").nth(1).click()
        cards = self.page.locator(".lpane:not([inert]) .card.node")
        expect(cards).to_have_count(6)
        for width, columns in [(320, 1), (840, 2), (841, 1), (1024, 2), (1280, 2), (1920, 4)]:
            with self.subTest(width=width):
                self.resize(width, 720)
                first_row = cards.evaluate_all("(cards) => cards.filter(c => c.offsetTop === cards[0].offsetTop).length")
                self.assertEqual(first_row, columns)
                self.assertEqual(self.page.evaluate("document.documentElement.scrollWidth"), width)
        self.page.locator(".lpane:not([inert]) .tbtnrow button").first.click()
        modal = self.page.get_by_role("dialog")
        expect(modal).to_be_visible()
        self.assertGreater(modal.bounding_box()["width"], 480)
        for width, height in [(320, 568), (844, 390)]:
            self.resize(width, height)
            footer = modal.locator(".mfoot button").first
            expect(footer).to_be_in_viewport(ratio=1)
            body = modal.locator(".mbody")
            body.evaluate("e => e.scrollTop = e.scrollHeight")
            self.assertLessEqual(body.evaluate("e => e.scrollWidth - e.clientWidth"), 1)
            expect(footer).to_be_in_viewport(ratio=1)

    def test_long_endpoint_names_fit_in_both_tunnel_forms(self):
        self.resize(320, 568)
        self.page.locator(".tabbar button").nth(2).click()
        for tab in (0, 1):
            self.page.locator(".lseg button").nth(tab).click()
            self.page.locator(".lpane:not([inert]) .tbtnrow button").first.click()
            body = self.page.locator(".modal .mbody")
            picker = body.locator(".grid2 .msbtn").first
            picker.click()
            options = self.page.locator(".selpop [role=radio]")
            options.nth(2).click()
            expect(picker).to_contain_text("long-datacenter-")
            self.assertLessEqual(body.evaluate("e => e.scrollWidth - e.clientWidth"), 1)
            for group in body.locator(".grid2:visible, .seg2:visible").all():
                self.assertLessEqual(group.evaluate("e => e.scrollWidth - e.clientWidth"), 1)
            self.page.locator(".modal .mx").click()
            expect(body).to_have_count(0)

    def test_expanding_cards_only_moves_their_own_column(self):
        def fleet(route):
            core = "kind=core" in route.request.url
            family = "core" if core else "gre"
            links = [
                {"id": family + str(i), "name": family + str(i), "type": family,
                 "a_name": "east", "b_name": "west", "transport": "udp"}
                for i in range(8)
            ]
            route.fulfill(json={"links": links, "total": len(links)})

        self.page.route("**/api/fleet?*", fleet)
        for section in ("nodes", "tunnels", "core"):
            self.page.locator(".nav .navi").nth(1 if section == "nodes" else 2).click()
            if section != "nodes":
                self.page.locator(".lseg button").nth(0 if section == "tunnels" else 1).click()
            cards = self.page.locator(".lpane:not([inert]) .flist > [data-rid]")
            expect(cards).to_have_count(6 if section == "nodes" else 8)
            for width, columns in [(1280, 2), (1920, 4)]:
                self.resize(width, 900)
                for index in (0, 1):
                    with self.subTest(section=section, width=width, index=index):
                        before = self.card_boxes(cards)
                        head = cards.nth(index).locator(".chead")
                        head.click()
                        try:
                            expect(head).to_have_attribute("aria-expanded", "true")
                            after = self.card_boxes(cards)
                            growth = after[index][3] - before[index][3]
                            self.assertGreater(growth, 10)
                            for i, (x, y, w, h) in enumerate(before):
                                below = i > index and i % columns == index
                                self.assertEqual(after[i][:3], [x, y + (growth if below else 0), w])
                        finally:
                            head.click()
                        self.assertEqual(self.card_boxes(cards), before)

    def test_open_cards_reflow_on_resize_and_reorder(self):
        self.resize(1280, 900)
        self.page.locator(".nav .navi").nth(1).click()
        pane = self.page.locator(".lpane:not([inert])")
        cards = pane.locator(".card.node")
        expect(cards).to_have_count(6)
        for i in (0, 1, 3):
            cards.nth(i).locator(".chead").press("Enter")
        for width, columns in [(390, 1), (1280, 2), (1920, 4), (1280, 2)]:
            with self.subTest(width=width):
                self.resize(width, 840)
                boxes = self.card_boxes(cards)
                self.assertEqual(len({box[0] for box in boxes}), columns)
                for i in range(columns, len(boxes)):
                    x, y, _, h = boxes[i - columns]
                    self.assertEqual(boxes[i][:2], [x, y + h + 12])
        for columns in (1, 2):
            pane.locator(".reordbtn").click()
            boxes = self.card_boxes(cards)
            self.assertEqual(len({box[0] for box in boxes}), columns)
            for i in range(columns, len(boxes)):
                self.assertEqual(boxes[i][1], boxes[i - columns][1] + boxes[i - columns][3] + 12)

    def test_save_is_reachable_on_long_api_page_after_resizing(self):
        self.page.locator(".nav .navi").nth(4).click()
        self.page.locator(".lseg:not(.nested) button").first.click()
        self.page.locator(".apcard [role=switch]").click()
        bar = self.page.get_by_role("region").filter(has=self.page.locator("button.primary"))
        expect(self.page.locator(".apep").first).to_be_visible()
        for width, height in [(1280, 720), (320, 568), (841, 360), (1920, 800)]:
            with self.subTest(width=width):
                self.resize(width, height)
                for fraction in (0, 0.5, 1):
                    self.page.evaluate("f => scrollTo(0, document.documentElement.scrollHeight * f)", fraction)
                    expect(bar.locator("button.primary")).to_be_in_viewport(ratio=1)
        bar.locator("button.ghost").click()
        expect(bar).to_have_count(0)

    def test_long_confirmation_can_be_read_and_dismissed_at_short_height(self):
        self.page.locator(".nav .navi").nth(4).click()
        self.page.locator(".stfoot button").click()
        dialog = self.page.get_by_role("alertdialog")
        self.resize(486, 180)
        expect(dialog).to_be_in_viewport(ratio=1)
        dialog.evaluate("e => e.scrollTop = e.scrollHeight")
        cancel = dialog.locator("button.ghost")
        expect(cancel).to_be_in_viewport(ratio=1)
        cancel.click()
        expect(dialog).to_have_count(0)


if __name__ == "__main__":
    unittest.main()
