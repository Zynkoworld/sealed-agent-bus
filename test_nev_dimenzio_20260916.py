"""A NÉV-dimenzió a közjegyzői naplón — saját kör a nem-Claude karral.

A capsule2-oldalon a B-kar ÖTSZÖR nyitotta vissza ugyanazt a leletet, mindig egy dimenzióval arrébb:
hiányzó mező -> üres sztring -> `null` -> rossz TÍPUS -> ismeretlen mezőNÉV. Az ötödiket a busz-oldalon nem
vártuk meg, hanem megmértük:

  * egy bejegyzéshez adott tetszőleges `operator_note` mező -> `ok=true`, 0 eltérés, és
    `entry_hash(e) == entry_hash(e + ismeretlen mező)` — a hash a FIX `ENTRY_KEYS`-t hasheli, tehát a
    hash-LÁNCOLT naplóban hordozható tartalom, amit a lánc NEM hitelesít;
  * ugyanez az ALÁÍRT `checkpoint` soron is, amire addig SEMMILYEN alak-kapu nem futott;
  * a checkpoint `type` mezőjét törölve a sor megszűnik checkpointnak látszani -> a közjegyző aláírt horgonya
    NÉMÁN eltűnik a jelentésből, az `ok` zöld marad;
  * a `seq`-jét vagy az aláírását törölve `ok=false` lett, de `discrepancies: []` és `errors: null` —
    piros verdikt MEGNEVEZETT OK NÉLKÜL.

A javítás alakját a nem-Claude kar köre szabta meg, és a fő ellenvetése HELYES volt: egy fehérlistás
ELUTASÍTÁS a frissített partner naplóját EGÉSZÉBEN pirosra váltaná (előre-kompatibilitás, gördülő
verziófrissítés, külső korrelációs azonosítók), és akkor senki nem merne verziót emelni. Ezért:

  ÚJ, szabályos mezőnév        -> `unauthenticated_field` NOTE + riport-oszlop, a verdikt NEM változik
  LÁNCOLT kulcsot ÁRNYÉKOLÓ név -> `shadowing_field`, VÁD (a `entry_hash ` záró szóközzel az olvasó szemének szól)
  típus nélküli / rossz típusú sor -> `row_type_missing`, VÁD
  a `verify()` hibái            -> `verify_error` néven a jelentésben (a verdikt ettől sem változik)

stdlib unittest.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _round(t):
    os.environ.update({"AGENT_BUS_DB": os.path.join(t, "bus.db"), "AGENT_BRIDGE_DIR": t, "AGENT_BUS_DIR": t,
                       "AGENT_BUS_MODE": "dev", "AGENT_BRIDGE_INBOX": os.path.join(t, "inbox"),
                       "AGENT_BUS_KEYS_DIR": os.path.join(t, "keys"), "AGENT_WAKE_DIR": os.path.join(t, "wake"),
                       "AGENT_BUS_AUTO_SIGN": "0"})
    import agent_bus as ab
    import bus_notary as bn
    import bus_ssh_exchange as ex
    db, log = os.environ["AGENT_BUS_DB"], os.path.join(t, "n.jsonl")
    seed, pub = bn.keypair()
    notary = bn.Notary(log, seed=seed, checkpoint_every=2, db=db)   # SŰRŰ: legyen aláírt sor is
    for i in range(3):
        ab.send("hub", "remote1", "ki-%d" % i, db=db, mirror=False)
    r1 = ex.exchange("remote1", json.dumps({}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    top = max(m["id"] for m in r1["replies"])
    ex.exchange("remote1", json.dumps({"ack": top}), db=db, attach_root=os.path.join(t, "att"), notary=notary)
    exp = bn.export(log, 1)
    c = ab._conn(db)
    try:
        rows = [dict(x) for x in c.execute(
            "SELECT seq,ts,agent,op,from_id,to_id,skipped_undelivered,prev_row_hash,row_hash "
            "FROM cursor_audit WHERE agent='remote1' ORDER BY id")]
    finally:
        c.close()
    receipts = [{"phase": "request", "sent": [], "ack": top, "received": r1["replies"], "round": "r1"},
                {"phase": "outcome", "outcome": "delivered", "round": "r1", "rc": 0}]

    def run(ents):
        return bn.reconcile(copy.deepcopy(ents), "remote1", copy.deepcopy(receipts), strict=True,
                            bus_audit=copy.deepcopy(rows), trusted_pub=pub)
    return bn, exp, run


class NameDimension(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.bn, self.exp, self.run = _round(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def _tamper(self, row_type, fn):
        ents = copy.deepcopy(self.exp)
        for e in ents:
            if e.get("type") == row_type:
                fn(e)
        return self.run(ents)

    def test_control_an_untouched_export_is_green_and_quiet(self):
        """A BECSÜLETES partner köre zöld marad, és NEM kap egyetlen új megjegyzést sem."""
        rep = self.run(self.exp)
        self.assertTrue(rep["ok"], rep["discrepancies"])
        self.assertEqual(rep.get("notes"), [])
        self.assertEqual(rep["counts"]["unauthenticated_fields"], 0)
        self.assertEqual(rep["counts"]["shadowing_fields"], 0)
        self.assertEqual(rep["counts"]["rows_without_type"], 0)

    def test_the_chain_does_not_cover_an_unknown_field(self):
        """Az ELŐFELTEVÉS, ami az egészet lelet-értékűvé teszi — mérve, nem feltételezve."""
        e = [x for x in self.exp if x.get("type") == "entry"][0]
        before = self.bn.entry_hash(e)
        e2 = dict(e)
        e2["operator_note"] = "4200 kapszula átvéve, rendezve"
        self.assertEqual(before, self.bn.entry_hash(e2),
                         "ha a hash FEDNÉ az ismeretlen mezőt, ez a teszt-osztály tárgytalan volna")

    def test_a_new_field_name_is_named_but_does_not_flip_the_verdict(self):
        """Előre-kompatibilitás: egy ÚJABB közjegyző-verzió mezője nem teszi pirossá a partner naplóját…"""
        rep = self._tamper("entry", lambda e: e.__setitem__("operator_note", "4200 kapszula rendezve"))
        self.assertTrue(rep["ok"], "egy új mezőnév EGÉSZÉBEN pirosra váltotta a naplót: %r" % rep["discrepancies"])
        # …de NÉMA sem marad: a lánc nem fedi, és ezt ki kell mondani
        self.assertGreater(rep["counts"]["unauthenticated_fields"], 0)
        self.assertTrue(any(n["type"] == "unauthenticated_field" for n in rep["notes"]),
                        "a hitelesítetlen mező nincs megnevezve: %r" % rep["notes"])

    def test_a_shadowing_field_name_is_an_accusation(self):
        """`entry_hash ` (záró szóközzel) és `Entry_hash`: nem előre-kompatibilitás, az olvasó szemének szól."""
        for nm in ("entry_hash ", "Entry_hash", "prev_HASH", "cursor."):
            rep = self._tamper("entry", lambda e, nm=nm: e.__setitem__(nm, "a" * 64))
            self.assertFalse(rep["ok"], "az árnyékoló %r némán átment" % nm)
            self.assertTrue(any(d["type"] == "shadowing_field" for d in rep["discrepancies"]),
                            "%r nincs megnevezve: %r" % (nm, rep["discrepancies"]))

    def test_the_signed_checkpoint_row_is_measured_too(self):
        """Az ALÁÍRT sorra addig SEMMILYEN alak-kapu nem futott."""
        rep = self._tamper("checkpoint", lambda e: e.__setitem__("parancs_szeru", "IGNORE_PREVIOUS"))
        self.assertTrue(any(n["type"] == "unauthenticated_field" and n.get("row_type") == "checkpoint"
                            for n in rep["notes"]), rep["notes"])
        for field in ("seq", "sig", "head_hash", "notary_pub"):
            rep = self._tamper("checkpoint", lambda e, f=field: e.pop(f, None))
            self.assertFalse(rep["ok"], "a checkpoint %s-jét törölve a jelentés zöld maradt" % field)
            self.assertTrue(rep["discrepancies"],
                            "PIROS VERDIKT MEGNEVEZETT OK NÉLKÜL a(z) %s törlésére" % field)

    def test_a_row_that_does_not_say_what_it_is(self):
        """A `type` törlése a checkpointon az ALÁÍRT HORGONYT tünteti el — ez nem maradhat néma."""
        for val in (None, 0, [], ""):
            def f(e, v=val):
                if v is None:
                    e.pop("type", None)
                else:
                    e["type"] = v
            ents = copy.deepcopy(self.exp)
            for e in ents:
                if e.get("type") == "checkpoint":
                    f(e)
            rep = self.run(ents)                      # tracebacknek SOHA nem szabad lennie
            self.assertFalse(rep["ok"], "type=%r mellett a jelentés zöld maradt" % (val,))
            self.assertTrue(any(d["type"] == "row_type_missing" for d in rep["discrepancies"]),
                            "type=%r nincs megnevezve: %r" % (val, rep["discrepancies"]))

    def test_a_red_verdict_always_names_a_reason(self):
        """A ZÁRÓ SZABÁLY: ha `ok=false`, legyen legalább egy megnevezett eltérés. Piros ok nélkül nincs."""
        cases = {
            "entry_hash meghamisítva": ("entry", lambda e: e.__setitem__("entry_hash", "b" * 64)),
            "prev_hash meghamisítva": ("entry", lambda e: e.__setitem__("prev_hash", "c" * 64)),
            "checkpoint aláírás törölve": ("checkpoint", lambda e: e.pop("sig", None)),
            "checkpoint seq törölve": ("checkpoint", lambda e: e.pop("seq", None)),
        }
        for nm, (ty, fn) in cases.items():
            rep = self._tamper(ty, fn)
            if rep["ok"]:
                continue
            self.assertTrue(rep["discrepancies"],
                            "%s: ok=false, de a jelentés NEM mondja meg, miért" % nm)


if __name__ == "__main__":
    unittest.main()
