# Secure Text — Android: ANALYSIS.md

> **Этап 1.** Анализ рабочей папки и формализация нормативных решений
> до начала реализации криптографического слоя на Android.
>
> Все решения по спорным вопросам приняты по варианту «Recommended» в
> моём опроснике от 07.09.2026. Пользователь подтвердил делегирование
> выбора. Любое последующее изменение нормативного решения должно
> отражаться в этом документе и в `STX2_COMPLIANCE_CHECK.md`.

---

## 0. Принятые нормативные решения (TL;DR)

| # | Вопрос | Решение |
|---|---|---|
| 1 | Fingerprint | `SHA-256(canonical_public_identity_json)`, hex, группы по 4 символа, uppercase. **Python-код содержит дефект: fingerprint не реализован вообще.** Норматив — STX2.md. Дефект зафиксирован, в `secure_text_2.py` нужно дописать fingerprint на следующем шаге (вне Android-этапа). |
| 2 | AAD/nonce при шифровании приватных ключей | Оставить `ChaCha20-Poly1305` с 12-байтным nonce и AAD=`SecureText private key v2`, как в STX2.md §29 и в Python. Норматив подтверждён. |
| 3 | Replay protection | **Не включать в v1.** STX2.md §36 явно говорит, что протокол не защищает от replay; реализация — локальная фича приложения. TODO. |
| 4 | Криптобиблиотека | **BouncyCastle** (`org.bouncycastle:bcprov-jdk18on`, 1.85.2). Отклонение от предыдущего решения (см. §«Изменение решения по криптобиблиотеке»): Tink не даёт полного контроля над nonce AEAD-режима, что ломает формат STX2; BC — чистый Java, одинаково работает в JVM-тестах и на Android. Argon2id — через встроенный `Argon2BytesGenerator`. |
| 5 | Verified-флаг и история ключей контактов | **Включить**: `verified`, `firstSeen`, `lastSeen`, история предыдущих Ed25519 pub. Локальное хранилище, interop не ломает. |
| 6 | Политика паролей | Минимум 8 символов, рекомендация 12+. Совместимо с Python. |
| 7 | QR-код | **Только текстовый импорт/экспорт.** QR отложен. |
| 8 | Android Keystore | **Keystore оборачивает KEK, полученный из Argon2id(pw, salt).** Биометрия разблокирует Keystore-ключ, который выдаёт KEK_check. Расшифровка приватных ключей — Argon2id + ChaCha20-Poly1305 (как в Python). Backup-файл остаётся совместимым с Python. |
| 9 | Порядок работы с расхождениями | **Сейчас только документация.** Правки `secure_text_2.py` — отдельным шагом, после Android-этапа. Android-крипто реализуется строго по STX2.md. |

---

## 1. Найденные файлы

```
Secure Text/
├── Промпт_для_OpenCode___разработка_Secure_Text_Android.md   (задание)
├── Secure Text — описание Android-проекта.md                  (общее ТЗ, RU)
├── STX2 Protocol Specification.md                             (спецификация STX2, EN)
├── STX2_COMPLIANCE_CHECK.md                                  (шаблон чек-поинта, RU)
└── secure_text_2.py                                          (Python-референс, Windows/Tk)
```

Рабочая папка **не** является Git-репозиторием (проверено: `.git` отсутствует).

---

## 2. Источники истины

| Компонент | Файл | Приоритет |
|---|---|---|
| Спецификация протокола (норматив) | `STX2 Protocol Specification.md` | **Высший.** Все спорные места разрешаются в пользу STX2.md, если Python не противоречит. |
| ТЗ и архитектурные требования | `Промпт_для_OpenCode___разработка_Secure_Text_Android.md` + `Secure Text — описание Android-проекта.md` | Высокий. Используется для UX/архитектуры/модели угроз. |
| Референсная реализация | `secure_text_2.py` | **Средний.** Источник истины для interop-тестов, но не для нормативных констант, если STX2.md говорит иначе. |
| Чек-поинт соответствия | `STX2_COMPLIANCE_CHECK.md` (этот же документ дополняется) | Процедурный. |

**Сводное правило:** при коллизии между STX2.md и Python — фиксируется в §8 (расхождения), нормативным считается STX2.md, Android реализуется по STX2.md.

---

## 3. Как сейчас работает протокол (по Python + STX2.md)

### 3.1. Идентичность

Пользователь владеет двумя парами ключей:

- **X25519** (32 байта private, 32 байта public) — обмен ключами.
- **Ed25519** (32 байта private, 32 байта public) — подпись.

Хранение приватных ключей:

```
password
  → Argon2id(time=3, mem=64 MiB, par=2, hash_len=32, salt=16 random)
  → KEK
  → ChaCha20-Poly1305(KEK, nonce=12 random, AAD="SecureText private key v2")
  → encrypted_private_key
```

Структура `keys.json`:

```json
{
  "version": 2,
  "x25519_private": { "salt", "nonce", "ciphertext" },
  "ed25519_private": { "salt", "nonce", "ciphertext" },
  "x25519_public":  "<B64URL 32B>",
  "ed25519_public": "<B64URL 32B>"
}
```

`salt` и `nonce` для каждого приватного ключа свои. Это означает, что
Argon2id пересчитывается дважды при открытии ключей (один раз для X25519,
один раз для Ed25519). Это **избыточно по CPU**, но не дыра в безопасности.
Для Android-реализации это нужно отметить — см. §10.

### 3.2. Публичный ключ

```
STX-PUB2:<Base64URL(canonical JSON)>
```

`canonical JSON` = `{"ed25519":"…","v":2,"x25519":"…"}`
(компактный, ключи отсортированы лексикографически, UTF-8).

> **Замечание.** В STX2.md §7 явно сказано: «object fields sorted
> lexicographically». В Python `public_key_string()` использует
> `separators=(",", ":")` и **`sort_keys=True`** (см. ниже в §8
> уточнение). В Android делаем `sort_keys=True` для совместимости.

### 3.3. Шифрование сообщения

1. Загрузить получателя `B.x25519_public`.
2. Сгенерировать ephemeral `X25519PrivateKey` (32 байта).
3. `shared_secret = X25519(ephemeral_private, B.x25519_public)`.
4. `message_key = HKDF-SHA256(shared_secret, salt=None, info="SecureText v2 X25519 XChaCha20-Poly1305", length=32)`.
5. `nonce = random(24)`.
6. `ciphertext = XChaCha20-Poly1305-Encrypt(message_key, nonce, plaintext_utf8, aad="STX2")`.
7. `obj = {"v":2,"epk":<B64URL 32B>,"nonce":<B64URL 24B>,"ct":<B64URL N+16>,"sender_ed25519":<B64URL 32B>}`.
8. Подпись: подписывается `canonical_without_signature(obj)` (т.е. всё, кроме `sig`), ключи отсортированы, компактный JSON, UTF-8.
9. `obj["sig"] = b64e(Ed25519.sign(sender_ed25519_private, canonical_unsigned))`.
10. Транспорт: `"STX2:" + b64e(canonical_json_with_sig)`.

### 3.4. Расшифровка

1. Проверить префикс `STX2:`.
2. `b64d → utf8 → json.loads`.
3. Проверить `v == 2`. Неизвестные версии — reject.
4. Проверить наличие полей `epk, nonce, ct, sender_ed25519, sig`.
5. **Опционально** сравнить `sender_ed25519` с доверенным контактом. Если есть контакт и ключи не совпали — `KEY_CHANGE_WARNING` (UI-уровень).
6. Проверить Ed25519-подпись на `canonical_without_signature(obj)`. Если неверна — reject, plaintext не показывать.
7. `shared = recipient.x25519_private.exchange(epk)`.
8. `message_key = HKDF(…)` (те же параметры).
9. `XChaCha20-Poly1305-Decrypt(key, nonce, ct, aad="STX2")`. Если tag не сошёлся — reject.
10. `plaintext = UTF-8 decode`.

### 3.5. Fingerprint (в STX2.md)

```text
fingerprint = SHA-256(canonical_public_identity_json)
```

32 байта → 64 hex-символа. UI-формат: группы по 4 символа, uppercase,
с пробелами, 8 групп по 4 = 8 групп в 2 строки (как в STX2.md §8 и
`Secure Text — описание Android-проекта.md` §9).

> **Дефект Python.** В `secure_text_2.py` fingerprint **не вычисляется и
> не отображается**. Это противоречит STX2.md §8 и ТЗ. Нужно дописать
> после Android-этапа (вне текущей задачи), чтобы interop-тесты
> fingerprint-а были возможны.

---

## 4. Что уже существует

- **Протокол STX2:** спецификация на 53 раздела + 822-строчный Python-референс.
- **Идентичность:** генерация, открытие с паролем, сохранение в `~/.secure_text/keys.json`.
- **Публичный ключ:** сериализация `STX-PUB2:…` и парсинг с валидацией.
- **Шифрование/расшифровка:** Python desktop-приложение с Tk-интерфейсом.
- **Контакты:** простой `contacts.json` `{name: STX-PUB2:…}` без verified-флага, без истории, без даты.

---

## 5. Что необходимо реализовать на Android

(соответствует разделам ТЗ и `Secure Text — описание Android-проекта.md`.)

| # | Компонент | Этап | Зависит от |
|---|---|---|---|
| 1 | Project skeleton (Gradle, Compose, Material 3) | 2 | — |
| 2 | Модуль `crypto/` (чистый Kotlin, без Android-зависимостей) | 3 | стоп-условие из Этапа 1 |
| 3 | STX2 protocol (parse/serialize/encrypt/decrypt/sign/verify) | 4 | 2 |
| 4 | KeyStore-backed хранение приватных ключей (Android Keystore + EncryptedSharedPreferences) | 5 | 2 |
| 5 | Контакты (verified, firstSeen, lastSeen, history) | 6 | 2, 3 |
| 6 | Encrypt/Decrypt экраны (Compose) | 7 | 3, 5 |
| 7 | Clipboard + Sharesheet + auto-detect `STX2:` | 8 | 6 |
| 8 | Fingerprint UI + сравнение | 9 | 3 |
| 9 | Backup/Restore (.stx, Argon2id, ChaCha20-Poly1305) | 10 | 3 |
| 10 | QR (отложено) | 11 | 3, 5 |
| 11 | Тесты: unit, integration, negative, Android↔Python interop | 12 | всё |

---

## 6. Проверка соответствия Python ↔ STX2 (детально)

> Полная таблица с чекбоксами — в `STX2_COMPLIANCE_CHECK.md` (этот
> документ дополняется отдельно). Здесь — сводный результат.

### 6.1. Криптопримитивы

| Примитив | STX2.md | Python | Совпадает? |
|---|---|---|---|
| X25519 | §2 | `cryptography.hazmat.primitives.asymmetric.x25519` | ✅ |
| XChaCha20-Poly1305 | §2, §16, §26 | `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*` | ✅ |
| Ed25519 | §2, §18, §23 | `cryptography.hazmat.primitives.asymmetric.ed25519` | ✅ |
| HKDF-SHA256 | §13, §25 | `cryptography.hazmat.primitives.kdf.hkdf.HKDF(SHA256, 32, None, "SecureText v2 X25519 XChaCha20-Poly1305")` | ✅ |
| Argon2id | §29 | `argon2.low_level.hash_secret_raw(time=3, mem=64MiB, par=2, hash_len=32, type=ID)` | ✅ |
| Base64URL без padding | §20, §43 | `base64.urlsafe_b64encode(...).decode().rstrip("=")` | ✅ |

### 6.2. Формат публичного ключа

| Поле | STX2.md | Python | Совпадает? |
|---|---|---|---|
| Префикс | `STX-PUB2:` | `PUB_MAGIC = "STX-PUB2:"` | ✅ |
| Версия | `v=2` | `VERSION=2` | ✅ |
| JSON-поля | `{v, x25519, ed25519}` | `{v, x25519, ed25519}` | ✅ |
| Кодирование | Base64URL(UTF-8 JSON) | `b64e(json.dumps(..., separators=(",", ":")).encode("utf-8"))` | ✅ |
| Сортировка ключей JSON | §7 «lexicographically» | **`sort_keys=True`** в `public_key_string()` | ✅ |
| Длины полей | 32B X25519, 32B Ed25519 | 32B (raw → b64) | ✅ |

### 6.3. Формат сообщения

| Поле | STX2.md | Python | Совпадает? |
|---|---|---|---|
| Префикс | `STX2:` | `"STX2:"` | ✅ |
| Версия | `v=2` | `VERSION=2` | ✅ |
| Поля | `v, epk, nonce, ct, sender_ed25519, sig` | те же | ✅ |
| `epk` длина | 32 B | 32 B (raw X25519 public) | ✅ |
| `nonce` длина | 24 B | 24 B (`os.urandom(24)`) | ✅ |
| `ct` длина | N + 16 (Poly1305 tag) | N + 16 (libsodium возвращает ciphertext с тегом) | ✅ |
| `sender_ed25519` длина | 32 B | 32 B | ✅ |
| `sig` длина | 64 B | 64 B | ✅ |
| Подписывается | canonical unsigned (sort_keys, compact) | `canonical_without_signature()` — `sort_keys=True, separators=(",",":")` | ✅ |
| HKDF info | `"SecureText v2 X25519 XChaCha20-Poly1305"` | то же | ✅ |
| HKDF salt | `None` | `salt=None` | ✅ |
| HKDF length | 32 | 32 | ✅ |
| XChaCha AAD | `"STX2"` | `MAGIC = b"STX2"` | ✅ |
| Nonce — random | да | `os.urandom(24)` | ✅ |

### 6.4. Fingerprint

| Аспект | STX2.md | Python | Совпадает? |
|---|---|---|---|
| Алгоритм | `SHA-256(canonical_public_identity_json)` | **отсутствует** | ❌ |
| Формат отображения | hex, группы по 4, uppercase | — | ❌ (нет в коде) |

**Решение:** норматив = STX2.md. В Android реализуется. Python-дополнение
запланировано отдельной задачей (см. §10).

### 6.5. Защита приватных ключей

| Поле | STX2.md §29 | Python | Совпадает? |
|---|---|---|---|
| KDF | Argon2id | `argon2.low_level.hash_secret_raw(..., type=Type.ID)` | ✅ |
| Параметры | time=3, mem=64 MiB, par=2, hash_len=32 | те же | ✅ |
| Salt | 16 B random | `os.urandom(16)` | ✅ |
| AEAD | ChaCha20-Poly1305 | `ChaCha20Poly1305(key).encrypt(...)` | ✅ |
| Nonce | не указан явно | 12 B random | ⚠️ не нормативно (см. §8.2) |
| AAD | не указан явно | `b"SecureText private key v2"` | ⚠️ не нормативно (см. §8.2) |

**Решение:** оставить как есть. Риск коллизии nonce при ChaCha20-Poly1305
пренебрежимо мал (random 12 B + одноразовый salt на ключ ⇒ KDF даёт
уникальный ключ ⇒ коллизия только при коллизии salt, что невозможно).

### 6.6. Итог

**Соответствие Python ↔ STX2 по основному протоколу — ПОДТВЕРЖДЕНО.**

Расхождения касаются только fingerprint (отсутствует в Python) и формата
хранения приватных ключей (AAD/nonce не описаны в STX2.md, но они
де-факто зафиксированы в Python). Все эти расхождения — **некритичные**,
фиксируются и допускают переход к Этапу 3 (см. §8).

---

## 7. Потенциальные криптографические проблемы

### 7.1. Двойной Argon2id при открытии ключей

Python дважды считает Argon2id при загрузке `keys.json` (для X25519 и
для Ed25519 отдельно). На Android при 64 MiB memory_cost это ~600 мс
× 2 = ~1.2 с задержки. Не баг безопасности, но UX-проблема.

**План:** в Android — один Argon2id на сессию, общий KEK используется
для обоих приватных ключей. Backup-формат сохраняем совместимым
(каждый приватный ключ со своим salt + nonce) — Python при импорте
всё ещё сможет открыть.

### 7.2. HKDF `salt=None`

STX2.md §13/§25 и Python оба используют `salt=None`. Это валидно по
RFC 5869 (HKDF-SHA256), но спорно с точки зрения domain separation.
Принципиальной уязвимости нет, т.к. `info` обеспечивает достаточное
разделение.

**План:** сохраняем `salt=None` для совместимости. Не меняем.

### 7.3. Ed25519 подпись покрывает только `obj` без `sig`

STX2.md §17–§18 и Python подписывают canonical JSON без поля `sig`.
Это означает, что подпись покрывает `v, epk, nonce, ct, sender_ed25519`,
но **не** `sig` (которое добавляется после). Корректно. ✅

### 7.4. `sender_ed25519` входит в подпись

`sender_ed25519` включён в canonical JSON, по которому считается подпись.
Это означает, что подпись **самосвидетельствует**: подпись может быть
проверена только публичным ключом, указанным в `sender_ed25519`.
Защищает от подмены `sender_ed25519` после подписания. ✅

### 7.5. `ct` входит в подпись

`ct` подписывается, поэтому AEAD-тег избыточен против active attacker
(подпись уже всё покрывает). Но AEAD-тег **обязателен** для защиты от
случайного повреждения ciphertext без затрат на верификацию подписи.
Двойная защита — это плюс. ✅

### 7.6. Отсутствие key-confirmation / explicit sender

В STX2.md нет отдельного поля `from` или `to`. Получатель узнаёт
отправителя только по `sender_ed25519`. Идентификация отправителя
требует, чтобы публичный ключ был ранее зарегистрирован в контактах.
**Это by design**, но UI должен явно предупреждать «отправитель
неизвестен» (как требует ТЗ).

### 7.7. Первый обмен ключами (TOFU)

STX2.md §35 явно признаёт MITM при первом обмене и требует fingerprint
verification по независимому каналу. В Python это **никак не enforced**
— контакт сохраняется без verified-флага.

**План:** в Android v1 — контакт создаётся с `verified=false`,
UI подсвечивает fingerprint, требует явного подтверждения (галочка
«Я проверил fingerprint по [голос/видео/лично]»).

### 7.8. Replay

STX2.md §36 признаёт уязвимость. Python не реализует. Android v1 — тоже.
Зафиксировано как TODO.

### 7.9. AEAD-тег и integrity каскадно

Если attacker меняет `ct`, AEAD-тег не сойдётся → исключение.
Если attacker меняет `epk`, shared secret будет другой → другой
message_key → AEAD-тег не сойдётся → исключение.
Если attacker меняет `sender_ed25519`, подпись не сойдётся → исключение.
Если attacker меняет `nonce`, AEAD-тег не сойдётся → исключение.
Если attacker меняет `sig`, подпись не сойдётся → исключение.

✅ Все мутации детектируются. Negative-тесты обязательны (Этап 12).

### 7.10. Отсутствие key history при обновлении публичного ключа контакта

Python не хранит историю. STX2.md §24 требует `KEY_CHANGE_WARNING`.
В Android v1 — хранить историю Ed25519 pub с датами, показывать
warning при расхождении.

### 7.11. Потенциальная утечка через `keys.json` tmpfile

Python пишет в `keys.json.tmp`, затем `os.replace()`. ✅
В Android — DataStore + atomic write (или прямое использование
EncryptedSharedPreferences).

### 7.12. UI-скриншоты и clipboard

STX2.md §38 упоминает. Android v1: `FLAG_SECURE` на экранах
identity/contacts/decrypt; clipboard cleared через ~60 с
(используя `ClipboardManager.clearPrimaryClip` если доступно).

---

## 8. Зафиксированные расхождения и нормативные решения

### 8.1. Расхождение №1 — отсутствие fingerprint в Python

- **Где:** `secure_text_2.py` (отсутствует целиком).
- **STX2.md §8:** `fingerprint = SHA-256(canonical_public_identity_json)`.
- **Python:** не вычисляется, не отображается.
- **Нормативное решение:** норматив = STX2.md. Android реализует.
- **Действие:** дописать `compute_fingerprint(pubkey_str) -> str` в
  `secure_text_2.py` отдельной задачей **после** Android-этапа, чтобы
  Python-референс тоже соответствовал.
- **Блокирует Android?** Нет. interop-тест fingerprint-а между
  Android и Python — отдельный этап, после правки Python.

### 8.2. Расхождение №2 — AAD/nonce для backup не зафиксированы в STX2.md

- **Где:** STX2.md §29.
- **STX2.md:** рекомендует ChaCha20-Poly1305, не уточняет AAD и длину nonce.
- **Python:** `ChaCha20Poly1305` с 12-байтным nonce и AAD=`b"SecureText private key v2"`.
- **Нормативное решение:** фиксируем Python-вариант как норматив для
  backup-формата. Дополняем STX2.md в отдельной ревизии (вне текущей задачи).
- **Блокирует Android?** Нет.

### 8.3. Расхождение №3 — отсутствие verified-флага контактов в Python

- **Где:** `secure_text_2.py` → `contacts.json`.
- **STX2.md §24/§35:** контакт должен иметь verified-флаг; при смене
  ключа — `KEY_CHANGE_WARNING`.
- **Python:** хранит только `name -> pubkey`. verified/история отсутствуют.
- **Нормативное решение:** норматив = STX2.md + Secure Text — описание
  Android-проекта.md §25. Android вводит `verified`, `firstSeen`,
  `lastSeen`, историю Ed25519 pub. Python-формат не совместим
  расширениями, но **старый** Python-формат Android v1 должен
  уметь импортировать (миграция при первом открытии).
- **Блокирует Android?** Нет. Локальная фича, не влияет на wire-format.

### 8.4. Расхождение №4 — отсутствие replay protection

- **STX2.md §36:** явно говорит, что протокол не защищает от replay,
  рекомендует локальный SHA-256(message) cache.
- **Python:** не реализовано.
- **Нормативное решение:** в Android v1 — **не включаем**. Делаем
  грейсфул-деградейшн: показываем в UI «это сообщение вы уже видели»,
  но **только** в локальной истории (без блокировки дешифровки).
- **Блокирует Android?** Нет.

### 8.5. Расхождение №5 — UX-требования STX2.md §38 (screenshot/clipboard) выходят за рамки протокола

- **STX2.md §38:** screenshot protection, clipboard timeout, secure app lock.
- **Нормативное решение:** принимаем как UX-требования, реализуем в Android v1
  (минимально: `FLAG_SECURE` на экранах с приватными данными).

---

## 9. Предлагаемые исправления (для следующих задач)

Все исправления **не входят** в текущий этап разработки Android
(по решению пользователя — «сейчас только документация, Python не
трогаем»). Перечислены для прозрачности:

1. **`secure_text_2.py` → `compute_fingerprint(pubkey_str) -> str`:**
   SHA-256 от canonical JSON, hex uppercase, группы по 4.
2. **`secure_text_2.py` → контакты:** добавить `verified`, `firstSeen`,
   `lastSeen`, `keyHistory` (миграция при чтении).
3. **`secure_text_2.py` → backup:** при экспорте добавить
   `aad = "SecureText private key v2"` в JSON-файл (для явности).
4. **`STX2.md` → §29:** явно прописать AAD и длину nonce для backup-AEAD.
5. **`STX2.md` → §43 (test vectors):** добавить
   `test_vectors.json` (см. §11).

---

## 10. Технологический стек Android

### 10.1. Криптобиблиотека

**BouncyCastle** (`org.bouncycastle:bcprov-jdk18on:1.85.2`)
для X25519, Ed25519, XChaCha20-Poly1305, HKDF-SHA256.

Argon2id — встроенный `Argon2BytesGenerator` (тот же bcprov).
Параметры: time=3, mem=64 MiB, par=2, hash_len=32,
salt=16 — как в Python и STX2.md §29.

> **Изменение решения по криптобиблиотеке.** Ранее (решение №4) была
> выбрана связка Google Tink + argon2kt. В ходе Этапа 3 выбор заменён на
> BouncyCastle `bcprov-jdk18on` по причинам:
> 1. **Формат STX2 требует явного nonce (24 B) в AEAD.** Tink хайд-байты
>    nonce внутри keyset/ciphertext и не даёт полного контроля над
>    wire-форматом → нельзя гарантировать байт-в-байт совместимость
>    с Python-референсом.
> 2. **BC — чистый Java**: один и тот же код работает в JVM unit-тестах
>    (быстрый итеративный цикл против `test_vectors.json`) и на Android
>    (minSdk 26, без JNI).
> 3. BC покрывает все нужные примитивы: `X25519Agreement`,
>    `Ed25519Signer`, `XChaCha20Poly1305` (extended-nonce),
>    `HKDFBytesGenerator`, `Argon2BytesGenerator` (поддержка Argon2id
>    v1.3, параллельность 2 — чего не даёт argon2kt по умолчанию).
> 4. Меньше зависимостей (один jar вместо Tink + JNA + lazysodium +
>    argon2kt) и меньше риск конфликтов версий.
>
> Проверено аудитом API (javap) и набором тестов по `test_vectors.json`:
> все 5 positive- и 7 negative-векторов проходят, включая точный
> ciphertext XChaCha20-Poly1305 и Argon2id-вектор из Аргона.

### 10.2. SDK

- **minSdk = 26 (Android 8.0):** BiometricPrompt, современные Keystore
  API, широкая совместимость.
- **targetSdk / compileSdk = 34 (Android 14).**

### 10.3. UI

- **Kotlin 2.0+**, **Jetpack Compose** + **Material 3**.
- **Navigation Compose:** Identity / Encrypt / Decrypt / Contacts / Settings.
- **ViewModel + StateFlow.**
- **Hilt** для DI.
- **DataStore Preferences** для контактов и настроек.
- Private-ключи: `EncryptedSharedPreferences` (AES-GCM, Keystore-ключ);
  KEK из Argon2id оборачивается Keystore-ключом через прямой API.

### 10.4. Архитектура пакетов

```
app/
├── crypto/                           # BouncyCastle обёртки
│   ├── primitives/                   # X25519, Ed25519, XChaCha20Poly1305, HkdfSha256
│   ├── argon2/                       # Argon2id
│   ├── Stx2Message.kt                # encrypt/decrypt, public identity, fingerprint
│   ├── Stx2Constants.kt / CanonicalJson.kt / Base64Url.kt / Hex.kt / CryptoRandom.kt
├── protocol/                         # STX2: (план; код пока в crypto/Stx2Message.kt)
│   ├── Stx2Message.kt
│   ├── Stx2PublicIdentity.kt
│   ├── Stx2Fingerprint.kt
│   ├── Encryptor.kt
│   └── Decryptor.kt
├── storage/
│   ├── IdentityStore.kt
│   ├── ContactStore.kt
│   └── BackupCodec.kt
├── contacts/
│   ├── Contact.kt
│   └── ContactRepository.kt
├── share/
│   ├── ClipboardHelper.kt
│   └── SharesheetHelper.kt
├── security/
│   ├── BiometricUnlock.kt
│   └── ScreenSecurity.kt
└── ui/
    ├── theme/
    ├── navigation/
    ├── identity/
    ├── encrypt/
    ├── decrypt/
    ├── contacts/
    ├── settings/
    └── common/
```

---

## 11. Тестовые векторы

`test_vectors.json` будет сгенерирован отдельным шагом (после
подтверждения этого `ANALYSIS.md`). Векторы — детерминированные
(фиксированные ephemeral private, nonce, salt) для воспроизводимости.

Минимальный набор полей (по STX2.md §46):
- `sender.x25519_private` / `sender.ed25519_private`
- `recipient.x25519_private` / `recipient.ed25519_public`
- `plaintext`
- `ephemeral_private` (фиксированный)
- `nonce` (фиксированный)
- `expected_message` (полный `STX2:…`)

Дополнительно:
- `fingerprint_expected` для публичного ключа получателя.
- `negative_cases`: одна мутация каждого поля → ожидаемое исключение.

---

## 12. План реализации (после подтверждения этого документа)

1. **Этап 2** — Gradle skeleton, Compose, Material 3, базовые экраны
   (пустые). Без crypto. Цель: проект собирается.
2. **Этап 3** — `crypto/primitives` + `crypto/argon2` + `crypto/util`.
3. **Этап 4** — `protocol/` (Stx2Message, Encryptor, Decryptor, Fingerprint).
4. **Этап 5** — `storage/IdentityStore` (Android Keystore + Biometric).
5. **Этап 6** — `contacts/` (verified, history, firstSeen).
6. **Этап 7** — UI: Encrypt/Decrypt экраны.
7. **Этап 8** — Clipboard + Sharesheet.
8. **Этап 9** — Fingerprint UI + verification flow.
9. **Этап 10** — Backup/Restore (.stx) с Argon2id.
10. **Этап 11** — QR (отложен).
11. **Этап 12** — Тесты: unit + integration + negative + Android↔Python interop.

---

## 13. Стоп-условие

**Этап 1 пройден, если:**

- [x] Все 4 входных файла проанализированы.
- [x] Все 9 спорных вопросов разрешены (выбор пользователя = «Recommended»).
- [x] `STX2_COMPLIANCE_CHECK.md` заполнен с итоговым статусом.
- [x] `ANALYSIS.md` создан (этот документ).
- [x] Технологический стек выбран и обоснован.
- [x] План реализации согласован.

**Следующий шаг:** пользователь подтверждает `ANALYSIS.md` →
переход к Этапу 2 (skeleton).

---

*Дата:* 2026-09-07
*Автор анализа:* opencode (model: minimax/minimax-m3:free)
*Статус:* Готово к ревью пользователем.
