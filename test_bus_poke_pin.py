"""bus_poke pin_to_claude_pane teszt — a poke a CLAUDE-panelra megy, sosem a chatbox/aktiv panelra.
Gyoker-fix (az üzemeltető 2026-06-27: 'nehany bokes a chatboxba megy')."""
from types import SimpleNamespace
from bus_poke import pin_to_claude_pane


def _fake_run(panes_output, rc=0):
    return lambda argv: SimpleNamespace(returncode=rc, stdout=panes_output)


def test_picks_claude_pane_not_active_chatbox():
    # session 2 panellel: 0.0=claude (NEM aktiv), 0.1=node/chatbox (aktiv) -> a fix a 0.0-t valassza
    out = "0.0\tclaude\n0.1\tnode\n"
    assert pin_to_claude_pane("node", run=_fake_run(out)) == "node:0.0"


def test_session_name_only_normalized():
    assert pin_to_claude_pane("agrarium", run=_fake_run("0.0\tclaude\n")) == "agrarium:0.0"


def test_lowest_index_when_multiple_claude():
    # ket claude-panel (pl. a kanonikus agent + egy masodik) -> a legkisebb index (a kanonikus session)
    out = "1.0\tclaude\n0.0\tclaude\n"
    assert pin_to_claude_pane("node", run=_fake_run(out)) == "node:0.0"


def test_fallback_when_no_claude_pane():
    # nincs claude-panel -> az eredeti target (ne rontsunk a meglevon)
    assert pin_to_claude_pane("node:0.0", run=_fake_run("0.0\tbash\n")) == "node:0.0"


def test_fallback_on_tmux_error():
    assert pin_to_claude_pane("node", run=_fake_run("", rc=1)) == "node"


def test_no_poke_marker_overrides_explicit_target(tmp_path, monkeypatch):
    """Regression (az üzemeltető 2026-07-10: 'a bokes szetvagta az uzenetemet'): a wake/<agent>.no-poke marker
    HARD override -- egy explicit --target sem kerulheti meg (korabban az explicit-return elotte allt)."""
    import os
    import bus_poke
    monkeypatch.setattr(bus_poke, "BRIDGE", str(tmp_path))
    os.makedirs(tmp_path / "wake")
    # nincs marker -> az explicit target ervenyes
    assert bus_poke.resolve_target("app", explicit="app:0.0") == "app:0.0"
    # marker letezik -> None (semmi injektalas), meg explicit targettel is
    (tmp_path / "wake" / "app.no-poke").write_text("")
    assert bus_poke.resolve_target("app", explicit="app:0.0") is None
