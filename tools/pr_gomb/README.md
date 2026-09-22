# pr_gomb — merge-döntés Telegram-gombbal (az emberi kulcs a KET_EMBER_KULCS szabályban)

**Kinek:** annak az operátornak, akinek a saját oldalán kell egy EMBERI kulcs a PR-merge-hez — Telegramon, egy
kattintással, úgy, hogy a gomb SEMMIT nem kerül meg a GitHub branch-védelméből. A Zynko-oldalon ez fut 2026-09-17 óta
(az operátor kulcsával); ez a csomag ugyanaz, titkok és személyes azonosítók nélkül, config-fájlból paraméterezve.

## Mit csinál

1. `pr_gomb.py kerd <repo> <pr>` → egy PR-kártya megy az operátor privát chatjébe a bottal:
   cím, ág, **fej-SHA**, `mergeable_state`, a másik fél review-ja, és két gomb: **[MERGE ✅] [NEM ❌]**.
   A kérés az append-only `kerelmek.jsonl`-be kerül (id, fej-SHA, message_id).
2. A gombnyomás `callback_query`-ként érkezik a bothoz. A `telegram_gomb_poll.py` (vagy a saját pollered) a
   `valaszok.jsonl`-be írja (from_id, data, ts), és nyugtázza. **A poller nem dönt.**
3. `pr_gomb.py feldolgoz` (cron, percenként) végigmegy az új válaszokon:
   * nem az operátor kattintott → rögzítve, figyelmen kívül;
   * `NEM` → rögzítve, kimondott elutasítás (harmadik állapot, nem csend), visszajelzés Telegramon;
   * `MERGE` → újra lekéri a PR-t; ha a **fej változott** a kérés óta → NEM futtatja, megmondja; különben
     `PUT /pulls/{n}/merge` **merge-commit** móddal, a kéréskori `sha`-hoz kötve. Ha a GitHub visszautasítja
     (hiányzó kötelező review, piros check, védett ág) → „NEM futott le: <ok>" — a gomb **nem kerüli meg** a platformot.
   * minden döntés a `dontesek.jsonl`-be (append-only). Egy kérés egyszer dönthető el.

## Mit NEM csinál (kimondva)

* Nem ad review-t/approve-ot (a PR szerzője a GitHubon nem hagyhatja jóvá a sajátját). A gomb = a merge maga.
* Nem squash-ol, nem rebase-el: a base-pin horgonyok a merge-commit SHA-jára mutatnak.
* Nem kerüli meg a fej-változást: a döntés a KÉRÉSKORI fejhez kötött, új fejhez új kérés kell.
* Nem töröl semmit: mindhárom könyv append-only.
* Nem ír tokent naplóba.

## Telepítés (5 perc)

1. Bot: `@BotFather` → új bot → token → fájlba (`telegram_bot_token_file`, 0600). Írj a botnak egy üzenetet a saját
   fiókodból, és olvasd ki a `chat.id`-t + a saját `from.id`-det (pl. `getUpdates`): ez a `telegram_chat_id_file`
   tartalma és az `owner_id`.
2. GitHub: fine-grained vagy classic token `repo` joggal a cél-repókra → fájlba (`github_token_file`, 0600). A token
   tulajdonosának **merge joga** legyen, de a branch-védelem (kötelező review a másik féltől) rá is áll — ez a lényeg.
3. `cp config.example.json config.json`, töltsd ki. `owner_id` = a TE Telegram user-id-d (integer).
4. Próba küldés nélkül: `python3 pr_gomb.py kerd <repo> <pr> --proba` — kiírja a kártyát, nem küld, nem ír könyvet.
5. Cron: `crontab.example` két sora (útvonalakat átírva). Ha már van saját pollered ugyanazzal a bot-tokennel,
   lásd lent, és csak a 2. sort tedd be.

## Meglévő poller

A `getUpdates` offset botonként közös, ezért egy bot-tokenhez EGY poller fusson. Ha már van, ezt tedd bele
(ugyanaz, mint a `telegram_gomb_poll.py` magja):

```python
cq = u.get("callback_query")
if cq:
    with open(VALASZOK, "a", encoding="utf-8") as f:
        f.write(json.dumps({"update_id": uid, "from_id": (cq.get("from") or {}).get("id"),
                            "data": cq.get("data"), "callback_query_id": cq.get("id"), "ts": int(time.time())}) + "\n")
    _tg("answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": "Megkaptam, feldolgozom."})
```

## Kikapcsolás

Fájllal, nem kóddal: hozd létre a `disabled_marker` fájlt → a bot nem küld, a poller nem kérdez; `rm` = vissza.

## Miért így (a Zynko-oldali tanulságok)

* **Két ember kulcsa.** A két-kulcsos szabály agentekre osztva nulla kulcsot ad (mindkét agent az emberhez utal).
  Ezért az egyik kulcs az operátor gombja, a másik a másik fél GitHub-review-ja — a platform kényszeríti ki.
* **A fejhez kötött döntés.** Egy „igen" csak arra a bájtsorra áll, amit az operátor látott.
* **Harmadik állapot.** A „NEM" és a „nem futott le, mert…" külön rögzül; a csend nem döntés.
* **Append-only.** A könyv audit, nem állapot: utólag látszik, ki mikor mit döntött, és mi lett belőle.
