"""bus_poke pin_to_claude_pane test — the poke goes to the CLAUDE pane, never to the chatbox/active pane.
Root fix (the operator, 2026-06-27: 'some pokes go into the chatbox')."""
from types import SimpleNamespace
from bus_poke import pin_to_claude_pane


def _fake_run(panes_output, rc=0):
    return lambda argv: SimpleNamespace(returncode=rc, stdout=panes_output)


def test_picks_claude_pane_not_active_chatbox():
    # a session with 2 panes: 0.0=claude (NOT active), 0.1=node/chatbox (active) -> the fix must choose 0.0
    out = "0.0\tclaude\n0.1\tnode\n"
    assert pin_to_claude_pane("node", run=_fake_run(out)) == "node:0.0"


def test_session_name_only_normalized():
    assert pin_to_claude_pane("agrarium", run=_fake_run("0.0\tclaude\n")) == "agrarium:0.0"


def test_lowest_index_when_multiple_claude():
    # two claude panes (e.g. the canonical agent + a second one) -> the smallest index (the canonical session)
    out = "1.0\tclaude\n0.0\tclaude\n"
    assert pin_to_claude_pane("node", run=_fake_run(out)) == "node:0.0"


def test_fallback_when_no_claude_pane():
    # no claude pane -> the original target (do not make the existing state worse)
    assert pin_to_claude_pane("node:0.0", run=_fake_run("0.0\tbash\n")) == "node:0.0"


def test_fallback_on_tmux_error():
    assert pin_to_claude_pane("node", run=_fake_run("", rc=1)) == "node"


def test_no_poke_marker_overrides_explicit_target(tmp_path, monkeypatch):
    """Regression (the operator, 2026-07-10: 'the poke cut my message in two'): the wake/<agent>.no-poke marker
    is a HARD override -- not even an explicit --target can bypass it (previously the explicit return stood before it)."""
    import os
    import bus_poke
    monkeypatch.setattr(bus_poke, "BRIDGE", str(tmp_path))
    os.makedirs(tmp_path / "wake")
    # no marker -> the explicit target is valid
    assert bus_poke.resolve_target("app", explicit="app:0.0") == "app:0.0"
    # the marker exists -> None (no injection at all), even with an explicit target
    (tmp_path / "wake" / "app.no-poke").write_text("")
    assert bus_poke.resolve_target("app", explicit="app:0.0") is None
