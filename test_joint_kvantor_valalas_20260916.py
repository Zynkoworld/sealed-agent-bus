"""06Z) — a javítások a saját oldalunkról kötve.

A szondáját szó szerint átvettük (`test_joint_pledge_optout_20260916.py`, 8 eset). Ez a fájl azt köti, ami az ő
szondájából NEM derül ki: a javítás ALAKJÁT, és azt, hogy a két új jelzés a HELYES csatornán megy.

  BLOCKER — a `audit_skipped_contradicts_log` globális ∀-kvantoron állt: egyetlen további, önmagában
            BECSÜLETES kör-bejegyzés visszamenőleg mentesítette a hazug kört is. Most a kihagyás ahhoz a
            körhöz tartozik, amelyiknek az ACK-je hozta a `skipped_undelivered > 0`-t.
  HIGH    — a kör-záró horgony számonkérését az ELLENŐRZÖTT fél `closes` mezőjének KIHAGYÁSA kapcsolta ki, és
            ez sehol nem látszott. Most: `rounds_unpledged` számláló, és ha EGYETLEN kör sem vállal, egy
            log-szintű, NEM vádoló harmadik állapot (`audit_close_pledge_absent`).
  + a HIÁNYZÓ MÁSODIK NYILVÁNTARTÁS (`bus_audit=None`) a HARMADIK csatornára megy (`notes`): kimondva, de nem
    verdikt — mert `unresolved`-be téve HÁROM becsületes kontroll-tesztet tesz pirossá (mérve, lásd a PR-t).

stdlib unittest.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bus_notary as bn  # noqa: E402


def _round_entry(seq, cur):
    return {"type": "entry", "seq": seq, "recipient": "peer", "kind": "pickup", "decision": "accepted",
            "cursor": cur}


def _ack_entry(seq, frm, to, ack):
    return {"type": "entry", "seq": seq, "recipient": "peer", "kind": "ack", "decision": "accepted",
            "cursor": {"from": frm, "to": to, "ack": ack}}


GENESIS = "0" * 64


def _audit_rows(*specs):
    """ÉRVÉNYES LÁNCÚ audit-sorok: a `_audit_cross` először a láncot ellenőrzi, és egy rosszul láncolt
    fixtúra `audit_chain_broken`-nél megáll — tehát a szonda nem is jutna el a mért állításig.
    (Saját mérési hiba, rögzítve: az első alakom `prev_hash`-t írt `prev_row_hash` helyett.)"""
    import agent_bus as ab
    rows, prev = [], GENESIS
    for i, (frm, to, skipped) in enumerate(specs, 1):
        ts = 1_700_000_000 + i
        rh = ab._audit_row_hash(i, ts, "peer", "ack", frm, to, skipped, prev)
        rows.append({"seq": i, "ts": ts, "agent": "peer", "op": "ack", "from_id": frm, "to_id": to,
                     "skipped_undelivered": skipped, "prev_row_hash": prev, "row_hash": rh})
        prev = rh
    return rows


class QuantifierIsPerRound(unittest.TestCase):
    """A vád ahhoz a körhöz tartozzon, amelyiknek az ack-je a kihagyást hozta."""

    def _cross(self, rounds_and_acks, audit):
        return bn._audit_cross(rounds_and_acks, "peer", audit)

    def test_the_lying_round_is_accused_on_its_own_ack(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}),   # HAZUG: „nincs kiadatlan"
                _ack_entry(2, 0, 6, 6)]
        out = self._cross(ents, _audit_rows((0, 6, 4)))
        self.assertIn("audit_skipped_contradicts_log", {d["type"] for d in out}, out)

    def test_one_more_honest_round_must_not_clear_the_earlier_one(self):
        """A LELET: a becsületes visszamenőleg mentesítette a hazug 1. kört."""
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}),   # HAZUG
                _ack_entry(2, 0, 6, 6),
                _round_entry(3, {"at": 6, "replies": 0, "pending": 1, "next_id": 1}),   # BECSÜLETES
                _ack_entry(4, 6, 6, 6)]
        out = self._cross(ents, _audit_rows((0, 6, 4), (6, 6, 0)))
        d = [x for x in out if x["type"] == "audit_skipped_contradicts_log"]
        self.assertTrue(d, "a becsületes 2. kör kioltotta a vádat az 1. körről: %r" % out)
        self.assertEqual([x["round_seq"] for x in d[0]["per_round"]], [1],
                         "a vád nem ahhoz a körhöz van rendelve, amelyik hazudott: %r" % d[0])

    def test_control_an_honest_log_is_not_accused(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 3, "next_id": 1}),
                _ack_entry(2, 0, 2, 2)]
        out = self._cross(ents, _audit_rows((0, 2, 0)))
        self.assertNotIn("audit_skipped_contradicts_log", {d["type"] for d in out}, out)

    def test_a_skip_with_no_matching_logged_ack_is_a_third_state(self):
        """Az audit tud egy kihagyásról, amihez a naplóban nincs ack: nem vád, de nem is zöld."""
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0})]
        out = self._cross(ents, _audit_rows((0, 6, 4)))
        m = [d for d in out if d["type"] == "audit_skip_unattributable"]
        self.assertTrue(m, "a hozzárendelhetetlen kihagyás némán eltűnt: %r" % out)
        self.assertTrue(all(d.get("soft") for d in m), "ez harmadik állapot, nem vád")


class PledgeAbsenceIsVisible(unittest.TestCase):
    def test_a_log_where_no_round_pledges_is_named(self):
        ents = [_round_entry(1, {"at": 0, "replies": 1, "pending": 1}),
                _round_entry(2, {"at": 1, "replies": 1, "pending": 1})]
        out = bn._audit_cross(ents, "peer", _audit_rows((0, 1, 0)))
        m = [d for d in out if d["type"] == "audit_close_pledge_absent"]
        self.assertTrue(m, "a vállalás teljes hiánya nem látszik a jelentésben: %r" % out)
        self.assertTrue(m[0].get("soft"), "ez NEM vád: a régi közjegyző ép, aláírt láncot ír")

    def test_a_mixed_log_only_gets_the_counter_not_the_state(self):
        """Gördülő frissítés: ha VAN vállaló kör, a napló egészére nem szól a jelzés."""
        ents = [_round_entry(1, {"at": 0, "replies": 1, "pending": 1, "closes": 1}),
                _round_entry(2, {"at": 1, "replies": 1, "pending": 1})]
        out = bn._audit_cross(ents, "peer", _audit_rows((0, 1, 0)))
        self.assertNotIn("audit_close_pledge_absent", {d["type"] for d in out},
                         "a vegyes napló egészét minősítettük: %r" % out)


class TheMissingRegisterIsNamedButNotAVerdict(unittest.TestCase):
    def test_absent_bus_audit_is_named(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0})]
        out = bn._audit_cross(ents, "peer", None)
        m = [d for d in out if d["type"] == "audit_register_absent"]
        self.assertTrue(m, "második nyilvántartás nélkül a jelentés némán zöld: %r" % out)
        self.assertTrue(m[0].get("note_only"),
                        "a HARMADIK csatornára kell mennie: `unresolved`-be téve három becsületes "
                        "kontroll-teszt pirosra vált (mérve)")

    def test_a_supplied_register_produces_no_such_note(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 3, "next_id": 1}),
                _ack_entry(2, 0, 2, 2)]
        out = bn._audit_cross(ents, "peer", _audit_rows((0, 2, 0)))
        self.assertNotIn("audit_register_absent", {d["type"] for d in out}, out)

    def test_the_channel_marker_is_not_a_prose_field(self):
        """SAJÁT hiba, rögzítve: a csatorna-jelző előbb `note` volt, és egy MAGYARÁZÓ `note` szöveg
        (az `audit_close_pledge_absent`-en) átirányította a saját tételemet a néma csatornára.
        Ugyanaz a NÉV-dimenzió, amit ma zártunk — ezért a jelző neve `note_only`."""
        ents = [_round_entry(1, {"at": 0, "replies": 1, "pending": 1})]
        for d in bn._audit_cross(ents, "peer", _audit_rows((0, 1, 0))):
            if d["type"] == "audit_close_pledge_absent":
                self.assertNotEqual(d.get("note_only"), True,
                                    "a magyarázó szöveg csatorna-jelzővé vált: %r" % d)


class TheNonClaudeArmsRound(unittest.TestCase):
    """A nem-Claude kar köre EZEKRE a javításokra (2026-09-16). Négy megkerülése CÁFOLVA, egy IGAZ volt."""

    def _t(self, ents, audit):
        return sorted({d["type"] for d in bn._audit_cross(ents, "peer", audit)})

    def test_refuted_two_acks_for_one_round_still_accuse(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}),
                _ack_entry(2, 0, 3, 3), _ack_entry(3, 3, 6, 6)]
        self.assertIn("audit_skipped_contradicts_log", self._t(ents, _audit_rows((0, 3, 2), (3, 6, 2))))

    def test_refuted_more_audit_rows_than_logged_acks_is_not_silent(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}), _ack_entry(2, 0, 3, 3)]
        t = self._t(ents, _audit_rows((0, 3, 2), (3, 6, 2)))
        self.assertIn("audit_skipped_contradicts_log", t)
        self.assertIn("audit_skip_unattributable", t)

    def test_refuted_a_missing_ack_target_does_not_buy_silence(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}),
                {"type": "entry", "seq": 2, "recipient": "peer", "kind": "ack", "decision": "accepted",
                 "cursor": {"ack": 6}}]
        self.assertIn("audit_skipped_contradicts_log", self._t(ents, _audit_rows((0, 6, 4))))

    def test_refuted_one_fake_pledge_buys_a_STRONGER_signal_not_silence(self):
        """A támadó egy hamis `closes: 1`-gyel elnyomná a log-szintű jelzést — de zárást is vállal vele."""
        ents = [_round_entry(1, {"at": 0, "replies": 1, "pending": 1, "closes": 1}),
                _round_entry(2, {"at": 1, "replies": 1, "pending": 1})]
        t = self._t(ents, _audit_rows((0, 1, 0)))
        self.assertNotIn("audit_close_pledge_absent", t)
        self.assertIn("audit_close_missing", t,
                      "a hamis vállalás némaságot vett volna: %r" % t)

    def test_TRUE_a_round_written_after_its_ack_must_not_downgrade_the_accusation(self):
        """A LELET, ami igaz volt: pusztán a SORRENDDEL a kemény vád soft-ra gyengült."""
        ents = [_ack_entry(1, 0, 6, 6), _round_entry(2, {"at": 0, "replies": 2, "pending": 2, "next_id": 0})]
        t = self._t(ents, _audit_rows((0, 6, 4)))
        self.assertIn("audit_skipped_contradicts_log", t, "a sorrend leminősítette a bizonyítékot: %r" % t)
        self.assertIn("round_entry_after_its_ack", t, "a rendellenes sorrend nincs kimondva: %r" % t)

    def test_control_normal_order_has_no_ordering_anomaly(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 2, "next_id": 0}), _ack_entry(2, 0, 6, 6)]
        self.assertNotIn("round_entry_after_its_ack", self._t(ents, _audit_rows((0, 6, 4))))


class TheShapeFilterWasTheFourthDegreeOfFreedom(unittest.TestCase):
    """SAJÁT kör: a ``-on kimondott 3. pontom BIZONYÍTÁSA, nem állítása.

    A partner három szabadságfokot talált (kvantor, sorrend, KI FELEL), és mindháromra kapu került.
    Azt állítottam, hogy a gyökér nem a kapuk hiánya, hanem hogy az ELLENŐRZÖTT FÉL ÍRJA A BIZONYÍTÉKOT
    SZABAD ALAKBAN. Megmértem: a `rounds` szűrő NÉGY mezőn áll — `recipient`, `kind`, `decision`, és a
    `cursor` TÍPUSA —, és mind a négy a támadó kezében van. Bármelyiket elrontva a hazug kör kiesik a
    szűrőből, és a KEMÉNY vád némán SOFT `audit_skip_unattributable`-re gyengül (dev-módban ok=true).

    A javítás NEM ötödik kapu, hanem egy különbségtétel:
        az ablakban NINCS bejegyzés          -> tényleg nem mérhető (soft, marad)
        az ablakban VAN, de egyik sem kör-alakú -> nem a bizonyíték HIÁNYA, hanem a KIKERÜLÉSE (vád)
    """

    def _t(self, ents, audit=None):
        return sorted({d["type"] for d in bn._audit_cross(ents, "peer", audit or _audit_rows((0, 6, 4)))})

    CURSOR = {"at": 0, "replies": 2, "pending": 2, "next_id": 0}     # HAZUG: „nem hagytam ki semmit"

    def _dodge(self, **over):
        e = {"type": "entry", "seq": 1, "recipient": "peer", "kind": "pickup", "decision": "accepted",
             "cursor": dict(self.CURSOR)}
        e.update(over)
        return [e, _ack_entry(2, 0, 6, 6)]

    def test_control_the_plain_lie_is_still_a_hard_accusation(self):
        self.assertIn("audit_skipped_contradicts_log", self._t(self._dodge()))

    def test_a_cursor_that_is_not_a_dict_must_not_downgrade_the_accusation(self):
        self.assertIn("round_shape_dodges_attribution", self._t(self._dodge(cursor="nincs")))

    def test_a_different_recipient_must_not_downgrade_the_accusation(self):
        self.assertIn("round_shape_dodges_attribution", self._t(self._dodge(recipient="masik")))

    def test_a_different_decision_must_not_downgrade_the_accusation(self):
        self.assertIn("round_shape_dodges_attribution", self._t(self._dodge(decision="provisional")))

    def test_a_different_kind_must_not_downgrade_the_accusation(self):
        self.assertIn("round_shape_dodges_attribution", self._t(self._dodge(kind="delivery")))

    def test_control_a_GENUINELY_empty_window_stays_a_third_state(self):
        """A különbségtétel másik fele: ahol tényleg NINCS mit kézbe venni, ott marad a soft állapot."""
        t = self._t([_ack_entry(1, 0, 6, 6)])
        self.assertIn("audit_skip_unattributable", t)
        self.assertNotIn("round_shape_dodges_attribution", t)

    def test_control_an_honest_log_gets_neither(self):
        ents = [_round_entry(1, {"at": 0, "replies": 2, "pending": 3, "next_id": 1}), _ack_entry(2, 0, 2, 2)]
        t = self._t(ents, _audit_rows((0, 2, 0)))
        self.assertNotIn("round_shape_dodges_attribution", t)
        self.assertNotIn("audit_skipped_contradicts_log", t)



if __name__ == "__main__":
    unittest.main()
