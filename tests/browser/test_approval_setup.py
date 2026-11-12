"""Setting a gateway's first approver, the way a person actually does it.

Each test opens the link an agent hands over -- the setup page with the code in
its ``#fragment`` -- in real Chrome, does what a person does, and checks both
what the page says and what the gateway now holds. A page that says "done"
while nothing was stored, or stores something while saying nothing, fails.
"""

from __future__ import annotations

from typing import Any

import pytest

from trentina.gateway import approval_routes, approver

PASSWORD = "correct horse battery 9"
FORM = "form[action='/approve/setup']"


def _open_link(tab: Any, server: str, code: str) -> None:
    """Open the link exactly as an agent hands it over."""
    tab.goto(f"{server}{approval_routes.SETUP_PATH}#code={code}")


def _submit_password(tab: Any, new: str = PASSWORD, again: str = PASSWORD) -> dict[str, Any]:
    """Fill the "set a password" form and submit it as its button does.

    The form sits in a collapsed section, so its fields are set rather than
    typed into. Returns the headers the browser itself put on the POST.
    """
    sent: dict[str, Any] = {}
    tab.on("request", lambda r: sent.update(r.headers) if r.method == "POST" else None)
    tab.evaluate(
        """([form, n, a]) => {
            const f = document.querySelector(form);
            f.querySelector("input[name=new]").value = n;
            f.querySelector("input[name=again]").value = a;
        }""",
        [FORM, new, again],
    )
    with tab.expect_navigation():
        tab.evaluate("(form) => document.querySelector(form + ' button').click()", FORM)
    return sent


def _says(tab: Any) -> str:
    return " ".join(tab.inner_text("body").split())


@pytest.mark.usefixtures("fresh")
class TestSettingAPassword:
    def test_the_link_fills_the_code_and_leaves_the_address_bar_clean(
        self, tab: Any, server: str
    ) -> None:
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        assert tab.input_value(f"{FORM} input[name=code]") == code
        assert "#" not in tab.url and code not in tab.url

    def test_a_person_sets_a_password_and_is_told_so(self, tab: Any, server: str) -> None:
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        _submit_password(tab)
        assert "Password set. This gateway can be approved now." in _says(tab)
        assert "?done=password_enrolled" in tab.url
        assert approver.configured() is True
        assert approver.verify(PASSWORD) is True

    def test_the_browser_sends_its_own_origin(self, tab: Any, server: str) -> None:
        """RT#1609: the setup POST is checked by Origin, and a browser chooses
        that header itself. It must be this gateway's origin, never ``null``."""
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        sent = _submit_password(tab)
        assert sent.get("origin") == server

    def test_a_wrong_code_says_so_and_keeps_the_form(self, tab: Any, server: str) -> None:
        approver.open_enrolment()
        _open_link(tab, server, "zzzz-zzzz-zzzz")
        _submit_password(tab)
        says = _says(tab)
        assert "missing or wrong" in says
        assert "Nothing to approve" not in says
        assert tab.query_selector(f"{FORM} input[name=new]") is not None
        assert approver.configured() is False

    def test_mismatched_passwords_say_so_and_change_nothing(self, tab: Any, server: str) -> None:
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        _submit_password(tab, again=PASSWORD + " typo")
        assert "did not match. Nothing was changed." in _says(tab)
        assert approver.configured() is False

    def test_a_window_that_closed_while_the_page_was_open_says_so(
        self, tab: Any, server: str
    ) -> None:
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        approver.close_enrolment()
        _submit_password(tab)
        says = _says(tab)
        assert "setup window closed" in says.lower()
        assert "Nothing to approve" not in says
        assert approver.configured() is False

    def test_a_re_tapped_link_in_an_open_tab_refills_the_new_code(
        self, tab: Any, server: str
    ) -> None:
        """A tab already on the page does not reload when only the #fragment
        changes; the page's script must reload it so the new code is read."""
        approver.open_enrolment()
        _open_link(tab, server, "aaaa-aaaa-aaaa")
        _, code = approver.open_enrolment()
        with tab.expect_navigation():
            tab.evaluate("(c) => { location.hash = 'code=' + c; }", code)
        assert tab.input_value(f"{FORM} input[name=code]") == code


@pytest.mark.usefixtures("fresh")
class TestTheOriginRegression:
    def test_under_no_referrer_the_browser_sends_null_and_is_told_not_saved(
        self, tab: Any, server: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mechanism behind RT#1609, pinned: serve the old policy and the
        browser itself sends ``Origin: null``. The refusal must then say that
        nothing was saved -- not the generic "Nothing to approve"."""
        monkeypatch.setitem(approval_routes._HEADERS, "Referrer-Policy", "no-referrer")
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        sent = _submit_password(tab)
        assert sent.get("origin") == "null"
        says = _says(tab)
        assert "nothing was saved" in says
        assert "Nothing to approve" not in says
        assert approver.configured() is False


@pytest.mark.usefixtures("fresh")
class TestCreatingAPasskey:
    def test_a_person_creates_a_passkey_and_is_told_so(self, tab: Any, server: str) -> None:
        """Chrome's virtual authenticator stands in for the person's device,
        so the whole ceremony runs: begin, navigator.credentials.create, and
        finish, each a same-origin fetch checked by Origin."""
        cdp = tab.context.new_cdp_session(tab)
        cdp.send("WebAuthn.enable")
        cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )
        _, code = approver.open_enrolment()
        _open_link(tab, server, code)
        with tab.expect_navigation(timeout=15000):
            tab.click("#pk-go")
        assert "Passkey created. This gateway can be approved now." in _says(tab)
        assert "?done=passkey_enrolled" in tab.url
        assert approver.configured() is True
