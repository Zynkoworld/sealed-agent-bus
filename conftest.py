"""Pytest-konfiguráció: a KIMONDOTT, MÉRT korlátok listája — és miért nem a szonda átírása a válasz.

A partner-írt szondák közül kettő SZÁNDÉKOSAN piros. A `ClampLiedFields` azt méri, hogy a kör-bejegyzés
`pending`/`next_id` mezője a vádlott ÖNBEVALLÁSA, és a közjegyzői napló ÖNMAGÁBAN nem cáfolja. Ez igaz, és
a szonda pontosan ezt a határt rögzíti — nem hiba, hanem bizonyíték.

Miért nem írjuk át a szondát: a partner fájljai SZÓ SZERINT szállnak, mert az teszi őket bizonyítékká, hogy
nem mi írtuk. Egy „javítás" a fájlban megszüntetné a bizonyíték-értéküket. Ezért a korlátot itt, a futtató
oldalán mondjuk ki, a fájl egyetlen bájtjának érintése nélkül.

Miért nem `skip`: a kihagyott teszt nem mér semmit, és némán az is maradna, ha a korlát közben megszűnne.
A `strict` xfail ennek az ELLENTÉTE: amíg a korlát áll, a szonda pirosa VÁRT; ha viszont egyszer csak
átmenne, a suite PIROSRA vált, és rákérdez, hogy mi változott. Egy kimondott korlát így nem alszik el.

A korlát LEZÁRÁSA egy réteggel feljebb megvan és mérve van: `test_clamp_lied_with_audit_20260916.py`
ugyanezt a forgatókönyvet futtatja a busz saját, hash-láncolt `cursor_audit` exportjával, és mindkét
hazugság `audit_skipped_contradicts_log` (hard) verdiktet kap. A clamp tehát NEM kapcsolható ki egyetlen
hazug számmal, ha az összevetés fut — csak a naplóval egyedül nem cáfolható.
"""
import pytest

# node-id -> miért várt a pirosa, és hol van a lezárása
EXPECTED_LIMITS = {
    "test_joint_delivery_outcome.py::ClampLiedFields::test_lied_next_id_must_not_defeat_the_clamp":
        "a kör-bejegyzés next_id-je önbevallás; a naplóval egyedül nem cáfolható "
        "(lezárás: test_clamp_lied_with_audit_20260916.py, bus_audit-tal)",
    "test_joint_delivery_outcome.py::ClampLiedFields::test_lied_pending_must_not_defeat_the_clamp":
        "a kör-bejegyzés pending-je önbevallás; a naplóval egyedül nem cáfolható "
        "(lezárás: test_clamp_lied_with_audit_20260916.py, bus_audit-tal)",
}


def _is_full_run(config):
    """Igaz, ha a futás a TELJES suite — csak akkor mond valamit a "nem gyűjtött" tény.

    Az első változat mindig ellenőrzött, és egy egyetlen fájlra szűkített futást HIBÁRA vitt: ott a szondák
    jogosan nincsenek a gyűjtésben. Egy őr, ami a szűkítést defektnek nézi, a fejlesztőt tanítja meg
    megkerülni magát — és attól kezdve a valódi eset sem tűnik fel."""
    if getattr(config.option, "keyword", None) or getattr(config.option, "markexpr", None):
        return False
    args = [a for a in (config.args or []) if not a.startswith("-")]
    root = str(config.rootpath)
    return all(a in ("", ".", root) for a in args)


def pytest_collection_modifyitems(config, items):
    seen = set()
    for item in items:
        for nodeid, why in EXPECTED_LIMITS.items():
            if item.nodeid.endswith(nodeid):
                item.add_marker(pytest.mark.xfail(reason=why, strict=True))
                seen.add(nodeid)
    missing = sorted(set(EXPECTED_LIMITS) - seen)
    if missing and _is_full_run(config):
        # Egy node-id, ami már nem létezik, néma kivételként élne tovább: a szondát átnevezték vagy törölték,
        # és a "várt piros" innentől semmit nem takar. Ez hangos hiba, nem elnézhető elírás — de csak teljes
        # futáson, mert egy szűkített futáson a hiányzás a szűkítés következménye, nem lelet.
        raise pytest.UsageError("conftest: nem gyűjtött, de kimondott korlát: %s" % ", ".join(missing))
