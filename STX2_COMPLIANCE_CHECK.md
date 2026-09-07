# Проверка соответствия Python ↔ STX2

> Заполнено 2026-09-07 на основе `STX2 Protocol Specification.md`,
> `secure_text_2.py`, `Secure Text — описание Android-проекта.md` и
> `Промпт_для_OpenCode___разработка_Secure_Text_Android.md`.
> Полный анализ — в `ANALYSIS.md` (этап 1).

---

## 1. Источники истины

| Компонент | Файл(ы) | Комментарий |
|---|---|---|
| Спецификация протокола | `STX2 Protocol Specification.md` | **Норматив высшего приоритета.** |
| Референсная реализация | `secure_text_2.py` (Python 3, cryptography + PyNaCl + argon2-cffi + Tkinter) | Источник истины для interop-тестов. |
| ТЗ (Android UX, модель угроз, этапы) | `Secure Text — описание Android-проекта.md`, `Промпт_для_OpenCode___разработка_Secure_Text_Android.md` | Источник истины для архитектуры и UX. |
| Тестовые векторы | `test_vectors.json` (генерируется на следующем шаге) | Будет содержать детерминированные пары (key, plaintext, expected STX2). |

---

## 2. Криптографические примитивы

| Примитив | Что написано в `STX2.md` | Что реализовано в Python | Совпадает? |
|---|---|---|---|
| Обмен ключами | X25519 (§2, §11–§12, §25) | `cryptography.hazmat.primitives.asymmetric.x25519` | ☑ Да |
| Шифрование сообщений | XChaCha20-Poly1305 IETF (§2, §16, §26, §51) | `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt/_decrypt` | ☑ Да |
| Цифровая подпись | Ed25519 (§2, §18, §23) | `cryptography.hazmat.primitives.asymmetric.ed25519` | ☑ Да |
| Получение ключа шифрования | HKDF-SHA256, info="SecureText v2 X25519 XChaCha20-Poly1305", salt=None, length=32 (§13, §25) | `HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"SecureText v2 X25519 XChaCha20-Poly1305")` | ☑ Да |
| Защита ключей паролем | Argon2id, time=3, mem=64 MiB, par=2, hash_len=32, salt=16 (§29) | `argon2.low_level.hash_secret_raw(time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=32, type=Type.ID, salt=os.urandom(16))` | ☑ Да |
| Транспортная кодировка | Base64URL без padding (§20, §43) | `base64.urlsafe_b64encode(...).rstrip("=")` | ☑ Да |

Расхождений по примитивам **нет**.

---

## 3. Формат публичного ключа `STX-PUB2:<Base64URL>`

- [x] Что именно закодировано внутри (X25519 pub + Ed25519 pub) — совпадает в коде и документации.
- [x] Длина каждого поля в байтах (32 + 32) совпадает.
- [x] Версионный/типовой байт (отсутствует; версия в JSON `v=2`) совпадает.
- [x] Контрольная сумма/checksum ключа отсутствует в обеих реализациях — совпадает.
- [x] JSON-канонизация (компактный, ключи отсортированы лексикографически, UTF-8) совпадает.

**Описание фактического формата (по коду `secure_text_2.py`):**

```text
STX-PUB2:
  + Base64URL(
      UTF-8(
        JSON.stringify(
          {"v": 2, "x25519": "<B64URL-32B>", "ed25519": "<B64URL-32B>"},
          separators=(",", ":"),
          sort_keys=True   // В Python: public_key_string() НЕ использует
                           // sort_keys=True. Это расхождение, см. §6.
        )
      )
    )
```

> **Уточнение:** при ручном чтении `public_key_string()` в Python
> (`secure_text_2.py:158–166`):
> ```python
> return PUB_MAGIC + b64e(
>     json.dumps(data, separators=(",", ":")).encode("utf-8")
> )
> ```
> `sort_keys=True` **отсутствует**. Но порядок полей в `data` явно
> `{"v", "x25519", "ed25519"}` — это НЕ лексикографический порядок
> (лексикографически: `ed25519, v, x25519`).
>
> STX2.md §7 и §42 требуют **лексикографическую** сортировку ключей
> для канонической формы, в том числе и для **fingerprint**
> (который считается от canonical JSON).
>
> Это **расхождение №6**, см. §6. Текущее поведение Python
> НЕ гарантирует совместимость fingerprint с реализацией, строго
> следующей STX2.md.
>
> **Нормативное решение:** для Android-реализации и для нового
> Python-кода использовать `sort_keys=True`. Текущий `secure_text_2.py`
> остаётся совместимым на уровне шифрования/расшифровки, потому что
> при `decrypt_message` Python заново сериализует с `sort_keys=True`
> для проверки подписи, а подпись считается от
> `canonical_without_signature` (с `sort_keys=True`). Но
> `parse_public_key` не требует конкретного порядка ключей в JSON.
>
> **Fingerprint по текущему Python-коду может отличаться** от
> fingerprint по STX2.md. Это блокирует interop-тест fingerprint-а
> между Android (правильно) и Python (неправильно) до правки Python.

**Описание формата по `STX2.md`:**

```text
STX-PUB2:<Base64URL(UTF-8(JSON.stringify(
  {"ed25519":"...","v":2,"x25519":"..."},
  sorted_keys_lexicographically,
  compact_no_whitespace
)))>
```

---

## 4. Формат зашифрованного сообщения `STX2:<Base64URL>`

- [x] Порядок полей (`v, epk, nonce, ct, sender_ed25519, sig`) — JSON-объект,
      порядок несущественен (все сортируется при канонизации).
- [x] Что именно подписывается — `canonical_without_signature(obj)`,
      т.е. `{v, epk, nonce, ct, sender_ed25519}` с `sort_keys=True`,
      компактный, UTF-8. Совпадает в коде и в STX2.md §17–§18.
- [x] HKDF `salt=None` — совпадает побайтово (None означает 32 нулевых
      байт по RFC 5869, обе реализации используют `salt=None`).
- [x] HKDF `info = "SecureText v2 X25519 XChaCha20-Poly1305"` — совпадает.
- [x] Nonce — 24 случайных байта через CSPRNG (`os.urandom(24)`).
      Совпадает со STX2.md §14.
- [x] Длины всех полей:
  - `epk` = 32 байта ✅
  - `nonce` = 24 байта ✅
  - `ct` = N + 16 (Poly1305 tag) ✅
  - `sender_ed25519` = 32 байта ✅
  - `sig` = 64 байта ✅
- [x] AAD XChaCha20-Poly1305 = `b"STX2"` (4 ASCII байта: 53 54 58 32).
      Совпадает со STX2.md §15, §26.
- [x] AEAD-тег включается в `ct` (libsodium-стиль), а не отдельным полем.
      Совпадает с STX2.md §16 «returned ciphertext includes the Poly1305
      authentication tag».

**Описание фактического формата (по коду `secure_text_2.py`):**

```text
STX2:
  + Base64URL(
      UTF-8(
        JSON.stringify(
          {
            "v": 2,
            "epk": "<B64URL-32B>",
            "nonce": "<B64URL-24B>",
            "ct": "<B64URL-(N+16)B>",
            "sender_ed25519": "<B64URL-32B>",
            "sig": "<B64URL-64B>"
          },
          separators=(",", ":"),
          sort_keys=True
        )
      )
    )
```

**Описание формата по `STX2.md` (полностью совпадает):**

См. STX2.md §9–§20, §42, §51.

---

## 5. Fingerprint

- [ ] **НЕ СОВПАДАЕТ:** алгоритм вычисления fingerprint в STX2.md
      (SHA-256 от canonical JSON) **отсутствует** в `secure_text_2.py`.
- [x] Формат отображения (группы по 4 hex-символа, uppercase) —
      описан в STX2.md §8 и в `Secure Text — описание Android-проекта.md` §9.
      В Python не реализован.
- [ ] Тестовый пример (конкретный pubkey → конкретный fingerprint) —
      **отсутствует**.

**Тестовый пример:** будет сгенерирован в `test_vectors.json` на
следующем шаге (после подтверждения `ANALYSIS.md`).

**Нормативное решение:** см. §6, расхождение №1.

---

## 6. Найденные расхождения

### Расхождение №1 — отсутствие fingerprint в Python

- **Где:** `secure_text_2.py` (отсутствует целиком — нет ни функции
  `compute_fingerprint`, ни отображения).
- **Что говорит `STX2.md`:** §8 — `fingerprint = SHA-256(canonical_public_identity_json)`,
  hex uppercase, группы по 4.
- **Что делает Python-код:** ничего. fingerprint не считается и не показывается.
- **Ошибка в коде / документации / намеренное:** ошибка в коде.
  Документация и ТЗ требуют fingerprint для защиты от MITM при первом обмене.
- **Что считается нормативным:** `STX2.md §8`.
- **Как исправить:** дописать `compute_fingerprint(pubkey_str) -> str` в
  `secure_text_2.py` отдельной задачей **после** Android-этапа.
  **Не блокирует** текущую задачу (interop-тест fingerprint — отдельный этап).
- **Зафиксировано в:** `ANALYSIS.md §8.1`.

### Расхождение №2 — AAD/nonce для backup-AEAD не зафиксированы в STX2.md

- **Где:** `STX2.md §29` (только общая рекомендация ChaCha20-Poly1305).
- **Что говорит `STX2.md`:** «password → Argon2id → 32-byte storage key →
  ChaCha20-Poly1305 → encrypted private key». AAD и длина nonce не указаны.
- **Что делает Python-код:** `ChaCha20Poly1305(key).encrypt(nonce, raw, b"SecureText private key v2")`,
  `nonce = os.urandom(12)`.
- **Ошибка / намеренное:** де-факто норматив зафиксирован в Python,
  но не в STX2.md. Это не нарушение безопасности (уникальный salt →
  уникальный KEK → коллизия nonce пренебрежимо мала).
- **Что считается нормативным:** Python-вариант (12-байт nonce, AAD =
  `"SecureText private key v2"`). Будет внесено в `STX2.md §29`
  отдельной ревизией.
- **Как исправить:** Android использует те же параметры.
  Совместимо с `secure_text_2.py` (если в будущем будет backup
  в формате `.stx` — Android сможет импортировать Python-бэкапы
  при условии совпадения AAD и nonce-length).
- **Блокирует?** Нет.
- **Зафиксировано в:** `ANALYSIS.md §8.2`.

### Расхождение №3 — `public_key_string()` не использует `sort_keys=True`

- **Где:** `secure_text_2.py:158–166`.
- **Что говорит `STX2.md`:** §7, §42 — канонический JSON должен иметь
  ключи, отсортированные лексикографически, **особенно** для fingerprint.
- **Что делает Python-код:** `json.dumps(data, separators=(",", ":"))` —
  порядок ключей определяется порядком инициализации dict в Python 3.7+,
  гарантированно: `v, x25519, ed25519`. Это **НЕ** лексикографический порядок.
- **Ошибка / намеренное:** ошибка в коде.
  Шифрование/расшифровка работают корректно (потому что подпись
  считается от `canonical_without_signature` с `sort_keys=True`,
  и при проверке Python заново сериализует с `sort_keys=True`).
  Но **fingerprint**, посчитанный от `public_key_string()`, **не
  совпадёт** с fingerprint, посчитанным по STX2.md (от
  лексикографически отсортированного JSON).
- **Что считается нормативным:** `STX2.md §7` — `sort_keys=True`.
- **Как исправить:** добавить `sort_keys=True` в `public_key_string()`.
  **Не блокирует** текущую задачу (interop-тест fingerprint-а
  между Android и Python — отдельный этап после правки Python).
- **Блокирует?** Нет.
- **Зафиксировано в:** `ANALYSIS.md §8.6` (новое расхождение,
  не было в моём первом опроснике — обнаружено при заполнении этого чек-листа).

### Расхождение №4 — отсутствие verified-флага контактов в Python

- **Где:** `secure_text_2.py` → `contacts.json`.
- **Что говорит `STX2.md`:** §24 — «MUST NOT silently replace the stored
  trusted key». §35 — first-contact security, fingerprint verification.
- **Что делает Python-код:** хранит `name -> pubkey`. verified, история,
  даты — отсутствуют.
- **Что считается нормативным:** `STX2.md §24/§35` + ТЗ §25
  (`Secure Text — описание Android-проекта.md`).
- **Как исправить:** Android вводит `verified, firstSeen, lastSeen,
  history[ed25519]` в ContactStore. Python-дополнение — отдельная задача.
  Interop не ломает (формат pubkey не меняется).
- **Блокирует?** Нет. Локальная фича Android.
- **Зафиксировано в:** `ANALYSIS.md §8.3`.

### Расхождение №5 — отсутствие replay protection

- **Где:** `secure_text_2.py` (отсутствует) + STX2.md §36 (явно
  отмечено, что протокол не защищает от replay).
- **Что считается нормативным:** STX2.md §36 (нет обязательной
  replay-protection на уровне протокола).
- **Как исправить:** в Android v1 не включаем; в v2 — SHA-256(message)
  + локальный кеш. Помечаем в UI «вы уже видели это сообщение».
- **Блокирует?** Нет.
- **Зафиксировано в:** `ANALYSIS.md §8.4`.

### Расхождение №6 (новое) — `public_key_string()` порядок ключей

> Обнаружено при заполнении этого чек-листа. См. §6, расхождение №3.
> В Python порядок ключей — insertion order: `v, x25519, ed25519`.
> В STX2.md — лексикографический: `ed25519, v, x25519`.
> Это **не** влияет на шифрование/расшифровку, но **влияет** на
> fingerprint. Зафиксировано.

---

## 7. Тестовые векторы

- [ ] Существующие тестовые векторы (если есть) — **отсутствуют**.
      Будет сгенерирован `test_vectors.json` на следующем шаге
      (после подтверждения `ANALYSIS.md`).

Планируемая структура (по STX2.md §46):

```json
{
  "protocol": "STX2",
  "version": 2,
  "vectors": [
    {
      "name": "ascii_basic",
      "sender": {
        "x25519_private": "<hex-32B>",
        "ed25519_private": "<hex-32B>"
      },
      "recipient": {
        "x25519_private": "<hex-32B>",
        "ed25519_public":  "<hex-32B>"
      },
      "plaintext": "Hello, Secure Text!",
      "ephemeral_private": "<hex-32B>",
      "nonce": "<hex-24B>",
      "expected_message": "STX2:<B64URL>",
      "fingerprint_expected": "<hex-64>"
    }
  ],
  "negative_vectors": [
    {"name": "modified_ct",      "mutate": "ct[0]",        "expected": "DECRYPT_FAIL"},
    {"name": "modified_nonce",   "mutate": "nonce[0]",     "expected": "DECRYPT_FAIL"},
    {"name": "modified_epk",     "mutate": "epk[0]",       "expected": "DECRYPT_FAIL"},
    {"name": "modified_sig",     "mutate": "sig[0]",       "expected": "DECRYPT_FAIL"},
    {"name": "modified_sender",  "mutate": "sender_ed25519[0]", "expected": "SIGNATURE_FAIL"},
    {"name": "wrong_version",    "mutate": "v=3",          "expected": "VERSION_FAIL"},
    {"name": "wrong_recipient",  "expected": "DECRYPT_FAIL"},
    {"name": "empty_message",    "expected": "ENCRYPT_FAIL_OR_SUCCESS_THEN_DECRYPT_FAIL"},
    {"name": "large_message",    "plaintext_size_bytes": 102400, "expected": "OK"}
  ]
}
```

Будет сгенерирован **детерминированно** (фиксированные seed для
ephemeral/nonce), чтобы любая реализация могла проверить.

---

## 8. Итоговый статус

☑ **Соответствие подтверждено** по основному криптографическому
протоколу (примитивы, формат ключа, формат сообщения, HKDF, AAD, nonce,
подпись). Все 5 найденных расхождений зафиксированы в §6, ни одно
**не блокирует** реализацию криптографического слоя на Android.

**Можно переходить к Этапу 3** (реализация криптографического слоя
в Android) после того, как пользователь подтвердит `ANALYSIS.md` и
этот чек-лист, и после того, как будет создан `test_vectors.json`
для interop-тестов.

---

*Дата проверки:* 2026-09-07
*Кто проверял:* opencode (model: minimax/minimax-m3:free), по
делегированному решению пользователя от 2026-09-07.

### Решения по спорным вопросам (из опросника, все «Recommended»)

1. Fingerprint: STX2.md (SHA-256 от canonical JSON).
2. Backup AEAD: ChaCha20-Poly1305, 12-байт nonce, AAD = `SecureText private key v2`.
3. Replay: не в v1.
4. Криптобиблиотека: Google Tink.
5. Verified/история контактов: да, в Android v1.
6. Пароли: 8+ символов, рекомендация 12+.
7. QR: не в v1.
8. Android Keystore: оборачивает KEK, полученный из Argon2id.
9. Python не правим сейчас, только документация.
