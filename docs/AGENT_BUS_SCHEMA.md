# AgentBus — FROZEN WIRE CONTRACT v1.0.0

**Status:** FROZEN (2026-06-21). **Owner:** the bus maintainer (canonical: `agent_bus.py`).
**Why:** a second client vendored the transport; vendored clients
must not diverge until the two layers **merge**. This contract is the
shared, frozen surface — `agent_bus.py verify` enforces it on the live `bus.db`.

The design rationale (why two layers, why it is sellable) is separate: [`AGENT_BUS_DESIGN.md`](./AGENT_BUS_DESIGN.md).
The base invariant: **NO DELETION** — never DELETE; "read" = `read_at`/cursor.

---

## 1. Versioning

`SCHEMA_VERSION = "1.0.0"` (in code `agent_bus.py`, in the DB the `meta(schema_version)` pin).
SemVer, but under the contract's rules:

| Change | Bump | Approval |
|---|---|---|
| New **nullable** column at the end; new `kind`/`topic` value; new CLI command; new index | **MINOR** (1.x.0) | the initiating agent, the other notified on the bus |
| Patch (bugfix, behaviour-preserving) | **PATCH** (1.0.x) | independent |
| Renaming/dropping/retyping a column; breaking `id` monotonicity; changing the `thread_id` default; `read_at`/cursor semantics; changing **JSON mirror keys** | **MAJOR** (2.0.0) | **both operators** in writing, on the bus |

`verify` reports DRIFT if the live DB's columns differ from the frozen order/name,
or if the version pinned in the DB ≠ the code's `SCHEMA_VERSION`. An additive (extra, trailing) column is not DRIFT —
it is reported as `added_columns`.

---

## 2. `messages` table (FROZEN — order + name)

```sql
CREATE TABLE messages(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic, ordering key; NEVER reused
  ts          INTEGER NOT NULL,                   -- time.time_ns() (epoch ns)
  sender      TEXT NOT NULL,                      -- agent id (e.g. alpha|beta|gamma|…)
  recipient   TEXT NOT NULL,                      -- agent id
  topic       TEXT,                               -- free vocabulary, dot-separated (e.g. agentbus.rollout)
  kind        TEXT,                               -- open enum (see 4.)
  thread_id   TEXT,                               -- thread root id; if empty at send → the row's own id as a string
  in_reply_to INTEGER,                            -- the messages.id replied to (or NULL)
  body        TEXT NOT NULL,                      -- UTF-8 message body (raw text; no size limit in the contract)
  read_at     INTEGER)                            -- read time in ns (NULL=unread); NO deletion, only this is set
```

Indexes (part of the contract, a performance guarantee): `ix_recipient(recipient,id)`, `ix_thread(thread_id,id)`.

**Semantic invariants:**
- The `recv` "unread" set: `WHERE recipient=me AND id > cursor`. The cursor moves forward monotonically.
- The `thread_id` default: if `send` gets no `thread_id`, the new row's `id` becomes the thread root
  (a separate `UPDATE` in the same transaction). The `thread` view builds on this.
- `read_at` is set only by `recv --mark` / `ack`, and only from `NULL` (COALESCE) — never backwards.

## 2b. Signed row — `signed shape v:2` (FROZEN, NORMATIVE)

The sender name alone is not evidence: `send(sender, …)` accepts the string from anyone. The signature closes this.
This section describes the **byte image**, because that is exactly what an interop partner needs — the code (`agent_bus._a2_content_bytes`,
`_a2_sign`, `verify_sender`) is the source of truth; this section mirrors it, it does not replace it.

**What is signed.** The canonical object is EXACTLY these eight fields (the serializer sorts them; the listing here gives
the semantics):

| field | value | if missing |
|---|---|---|
| `v` | `2` — the signed-shape version (**not** the DB `SCHEMA_VERSION`) | required |
| `sender` | agent id | — |
| `recipient` | agent id | — |
| `topic` | free vocabulary | `""` (empty string, **not** `null`) |
| `kind` | open enum (see 4.) | `""` |
| `in_reply_to` | the `messages.id` replied to, integer | `null` |
| `body` | UTF-8 body | `""` |
| `ts` | epoch **nanoseconds**, the SIGNER's clock | required |

**What is LEFT OUT, and why.** `id` — the DB assigns it on `INSERT`; it does not exist yet at signing time.
`thread_id` — server-derived (if empty, it becomes the row's own `id`), so the signer cannot know it; the sender's
threading INTENT is carried by the signed `in_reply_to`. This exclusion is **frozen**: without it the
root-level chicken-and-egg is unresolvable.

**Canonicalization.** Sorted keys, compact separators (`,` and `:` without spaces), `NaN`/`Infinity` forbidden,
non-ASCII characters **raw**, in UTF-8 (no `\uXXXX` escape). The byte image is the UTF-8 encoding of the object
above.

> **WARNING, interop trap — integers must be serialized EXACTLY.** In nanoseconds `ts` is
> usually **greater than 2⁵³**, so it CANNOT be represented exactly as an IEEE-754 double. Whoever writes the numbers per the
> ECMAScript `Number::toString` rule (that is the number rule of RFC 8785 JCS) gets
> **`1789803064437527600`** instead of `1789803064437527544` — **a different byte image, a different signature, a silent
> verify failure**. The two numbers one usually sees in this case are DIFFERENT, and it is worth knowing which is which
> (measured with Node):
>
> ```js
> const n = 1789803064437527544n;
> String(Number(n))    // "1789803064437527600"  <- this is what the JCS/ECMAScript number rule WRITES
> BigInt(Number(n))    // 1789803064437527552n   <- this is the double's EXACT VALUE
> ```
>
> The output is `…600`, the stored value is `…552`, and **both differ** from the original `…544`. Whoever
> expects `…552` in the output is looking for the wrong number while debugging. The `v`, `ts` and `in_reply_to` fields must be written as arbitrary-precision integers.
> On this one point our canonicalization deliberately does NOT follow the JCS number rule; in everything else
> (key ordering, compactness, UTF-8) it coincides with it, because the keys here are fixed ASCII names.

**Normalizing the text fields — the rule for falsy values, stated.** The value of `topic`, `kind` and
`body` in the byte image is ALWAYS a string. The rule is a single sentence, and it is the same for EVERY entry point:

> **the field is missing, or its value is falsy (`null`, `""`, `0`, `false`, empty array/object) → in the byte image
> an empty string (`""`); for every other value the `String(value)` form stands.**

This also means that `null`, `0`, `false` and `""` **cannot be distinguished** in the signed
byte image — all are `""`. Whoever wants to carry semantics in these should not do it in the `topic`/`kind`/`body` field.

Two traps this sentence closes:

1. **The API default is not the signed value.** The kwarg default of `sign_for_send(kind="msg")` is a convenience for an
   OMITTED field. An **explicit** `kind=""` is the caller's INTENT and goes into the byte image as `""` —
   it is not replaced by `"msg"`. (This distinction comes from a measured finding: the client signer carried its own
   `or "msg"` normalization, so a partner computing per spec failed in three of the four shapes,
   with the reason `forged or tampered`.)
2. **Normalization lives in ONE place.** In the reference implementation that is `agent_bus.canonical_text_field`;
   the byte-image builder, the client signer and both cross-machine paths call it. A reimplementer should also
   put it in one function: the rule itself is simple, its copies are what tend to drift apart.

**Three more things that MUST be stated, because without them another arm silently diverges.** All three were
measured first by an independent reimplementation from a foreign family (its own JS vectors, `node:crypto`), and
then we measured them on our own tree too — the values below come from measurement, not from a statement of intent.

1. **There is NO Unicode normalization.** The byte image takes the code points of `body` (and of every string) AS it
   received them. The NFC form of `"\u0151"` (U+0151) and its NFD form (U+006F U+0308 … `o` + a combining mark) give **DIFFERENT**
   byte images, hence different signatures — measured: `nfc_differs_nfd = true`. RFC 8785 JCS does not
   normalize either, so this is no deviation from it. Whoever normalizes to NFC on their side before sending or verifying
   builds a **silent verify failure**: the row stays valid for the sender and invalid for them. Normalization
   — if needed — is the CALLER's job, before building the byte image, the same way on BOTH sides.

2. **`ts` is an INTEGER, not floating point.** The interop trap above is about writing; this one is about the TYPE. If a
   reimplementer holds `ts` as a floating-point number (JS `Number`), precision is already lost when it is
   stored: measured `1758265200123456789` → `1.7582652001234568e+18`, i.e. a different value AND a different byte image.
   In JS you need `BigInt`. The same holds for the `v` and `in_reply_to` fields.

3. **The key order is ALPHABETICAL, not the order of the field list.** The table above gives the SEMANTICS, not the
   serialization order. In the byte image the keys stand like this — measured:
   `body, in_reply_to, kind, recipient, sender, topic, ts, v`.
   Whoever copies the table's order (`v, sender, recipient, topic, kind, in_reply_to, body, ts`) into
   serialization gets a different byte image. In the code the field list's name says the same: the SET is frozen, not the
   order.

**Extra fields do not count.** The byte image is built from EXACTLY the eight fields. Any further key in the
input object — `id`, `thread_id`, `read_at`, `sig`, `pubkey`, or a field unknown to us —
**does not change the byte image**; measured: `excluded_equal_empty = true`. This lets the sender and the
verifier sign and verify THE SAME thing even from slightly differently shaped records.

**Signature.** Ed25519 over the byte image above. The row carries the triple `{alg:"ed25519", sig:<hex>, pubkey:<hex>}`;
the pubkey travels so the registry holder can verify. The registry **PINS** the key to the **sender name**:
`keys/<sender>.pub`, and the file is readable ONLY if both the file and its directory are root-owned and
not group/world-writable (the final component cannot be a symlink).

**The verdict vocabulary (four values, NOT to be treated as an open enum):**
- `signed` — a valid signature with the registry key pinned to `sender`.
- `unsigned` — no signature, AND the registry binds no key to this name. The back-compat path, **not** forgery.
- `unsigned-pinned` — no signature, but the registry BINDS a key to this name: the name belongs to a party able to sign,
  yet the row is bare. Not proven forgery, but it does not blend into `unsigned` either — this is the machine gate's input.
- `forged` — has a signature, but it is invalid, OR the pubkey is not the one the registry binds to the declared sender.

In product mode (`bus_enforce`) `unsigned-pinned` and `forged` are rejected, with a named reason.

**Client-signed exchange (v1.5.2).** The sender signs on ITS OWN machine (`sign_for_send` → `{ts, sig, pubkey}`), the
bus machine checks it against the registry (`check_presigned`) and **stores exactly the row that was signed** —
it does not sign in its place and does not re-serialize. In product mode a bare row arriving under a pinned name bounces
AT ADMISSION, with the reason `unsigned-pinned`.

**Conformance vector** (runnable against your own implementation; the seed is a documented TEST value, not a live key):

```
seed    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
input   = sender="alpha", recipient="beta", topic="agentbus.rollout", kind="msg",
          in_reply_to=null, body="árvíztűrő", ts=1789803064437527544

content = {"body":"árvíztűrő","in_reply_to":null,"kind":"msg","recipient":"beta","sender":"alpha","topic":"agentbus.rollout","ts":1789803064437527544,"v":2}
          (150 bytes UTF-8; sha256 = 92bf710af81f672e5219c728ef7150caa3213210d71786185f4b0646975037f9)

pubkey  = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
sig     = 603d7cd0bc68bf9222873ee87e7ec5ccafbc8b620f2bfe00b4629ea5b6dbf7eae1d7f7805d6028415187af81b5a7f5de115d7a82fe8452a4b79923a34d02b505
```

**Second conformance vector — the EMPTY `kind` (same seed and same fields, only `kind=""`).**
This vector measures the point where a reimplementation most often diverges: the handling of falsy
values. Per the rule above, an OMITTED, an EMPTY and a `null` kind all give this same byte image.

```
seed    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
input   = sender="alpha", recipient="beta", topic="agentbus.rollout", kind="",
          in_reply_to=null, body="árvíztűrő", ts=1789803064437527544

content = {"body":"árvíztűrő","in_reply_to":null,"kind":"","recipient":"beta","sender":"alpha","topic":"agentbus.rollout","ts":1789803064437527544,"v":2}
          (sha256 = 5336f5ef4342aeec1bd49d16850757c6ac7774a4da9a62d6285ffe9ee7f6da0b)

pubkey  = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
sig     = 9adf4b7954b60f078a9b83bc42a7863454ba842bbc967eb31937581b38a64c75f2108ef1db96eeef5beb527c781fac5682d336ffd788de04a77751b1e24b8909
```

The same `content` results if the `kind` field is **missing**, and if its value is **`null`** — measured.

If your `content` sha256 matches, your canonicalization is right; if the whole byte image matches but the signature does not, the
key handling is at fault. The 150-byte length and the sha256 are listed separately, because the most common deviation — the
integer trap above — does NOT change the length.

**Change policy.** The field list of `v:2`, the exclusions and the canonicalization are **frozen**: changing any
of them is a new signed-shape version (`v:3`), MAJOR, and needs approval from both operators — vendored
clients sign against it.

## 3. `cursors` table (FROZEN)

```sql
CREATE TABLE cursors(agent TEXT PRIMARY KEY, last_seen_id INTEGER NOT NULL DEFAULT 0)
```
Per-agent "where am I" — `recv --mark` and `ack --upto` move it forward (never backwards on the normal path).

## 3b. `meta` table (additive, introduced in v1.0.0)

```sql
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)   -- {'schema_version': '1.0.0'}
```
`INSERT OR IGNORE` in `init` — it does **not overwrite** the pin of an existing DB (no-deletion).

---

## 4. `kind` vocabulary (open enum)

An INFORMATIVE listing (`kind` is an OPEN enum, the bus does not enforce it): `msg` (default), `announce`,
`answer`, `ack`, `question`, `proposal`.

**Stated:** of the list above, `proposal` appears NOWHERE in the code — so the doc
listed as "known" a value the implementation does not know. Not a bug (`kind` is open), but
it was misleading: whoever builds from the doc may believe it is handled. So from now on the list is explicitly
INFORMATIVE, and the ENFORCED kinds are listed in the following paragraphs — those are actually distinguished by `bus_enforce` and
`agent_wake`.
v1.1.0 (protocol MINOR, 2026-09-14): `sds-envelope` (body = the SPEC §5.5 framed `{record, envelope}` pair — `send`
rejects a malformed frame), `operator-wake`, `operator-sleep-safe` (effective only from an authorized operator — `agent_wake`).
The DB `schema_version` pin stays 1.0.0 (the schema did not change); the protocol version is `agent_bus.PROTOCOL_VERSION`.
v1.2.0 (protocol MINOR, 2026-09-14): `attachment` (body = ONLY the closed attachment descriptor `{sha256, size, media_type,
locator}`; the content lives outside the bus, in the `bus_attach` store — `send` rejects a malformed descriptor).
Adding a new value is **not** a version break (a consumer must treat an unknown `kind` as `msg`).

---

## 5. JSON mirror (FROZEN — back-compat bridge)

Until every agent has migrated, `send` also drops the message into the old file inbox (atomic `tmp→rename`):
`<AGENT_BRIDGE_DIR>/inbox/<recipient>/<sender>_<bus_id>_<topic-slug>.json`. The record's keys:

```json
{ "from": "<sender>", "to": "<recipient>", "kind": "<kind>", "topic": "<topic>",
  "note": "<body>", "ts": <ns>, "bus_id": <id>, "in_reply_to": [<id>] }
```

`in_reply_to` only if present; a **list** (the existing bridge convention). These keys are part of the
contract — a vendored client that reads the JSON inbox may rely on them.

---

## 6. CLI / lib surface (FROZEN)

```
agent_bus.py init
agent_bus.py send  --from X --to Y --topic T --kind K [--thread TID] [--reply ID] --body "…" [--no-mirror]
agent_bus.py recv  --agent X [--mark]
agent_bus.py tail  [--agent X] [--limit N]
agent_bus.py thread --id TID
agent_bus.py ack   --agent X --upto ID
agent_bus.py verify [--json]                 # exit 0=OK, 1=DRIFT
```

Lib: `send(...) -> id`, `recv(agent, mark=) -> [dict]`, `ack(agent, upto)`, `tail(...)`,
`thread(tid)`, `verify_schema(db=) -> dict`. The keys of the returned row dict = the `messages` columns.
Stdlib-only, never-throw on the CLI. A new flag/command is additive (minor).

---

## 7. Divergence check (both sides should run it)

```
python scripts/agent_bus.py verify          # or "$AGENT_BRIDGE_DIR"/agent_bus.py verify
```
Can be wired into CI (exit code). On DRIFT: do NOT write to the bus with the divergent client — agree on the bus,
and either align it back, or (if truly additive + back-compat) bump the version per point 1 of this document.
