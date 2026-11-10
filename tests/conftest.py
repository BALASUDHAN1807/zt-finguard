"""Suite-wide setup: staff working hours are opened to 00:00-24:00 for the test run (and restored
afterwards), so teller / operations tests pass at any time of day. The working-hours rule itself is
tested explicitly in test_session_timeouts.py."""
from __future__ import annotations

import pytest


def change_settings(admin, comment: str, **values) -> dict:
    from test_e2e import fresh_code
    r = admin.req("PUT", "/api/admin/settings", json={"values": values, "totp": fresh_code("admin"),
                                                        "comment": comment})
    if r.status_code == 409:                      # already set
        return {}
    assert r.status_code == 200, r.text
    return r.json()


def current_settings(admin) -> dict:
    return {x["key"]: x["value"] for x in admin.req("GET", "/api/admin/settings").json()["settings"]}


@pytest.fixture(scope="session", autouse=True)
def staff_hours_open_for_tests():
    try:
        from test_e2e import logged_in
        admin = logged_in("admin")
        before = current_settings(admin)
    except Exception:  # noqa: BLE001 - unit tests run without a stack
        yield
        return
    keys = ("staff_hours_start", "staff_hours_end")
    if (before["staff_hours_start"], before["staff_hours_end"]) != (0, 24):
        change_settings(admin, "e2e tests: staff hours open all day", staff_hours_start=0, staff_hours_end=24)
    yield
    if any(before[k] != v for k, v in zip(keys, (0, 24))):
        from test_e2e import logged_in
        change_settings(logged_in("admin"), "e2e tests: restore staff hours", **{k: before[k] for k in keys})
