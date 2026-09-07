# Secure Text — Android: SECURITY.md

> Документ-черновик. Описывает модель угроз, защитные меры и
> запреты, реализованные или планируемые к реализации в Android-версии.
> Согласован с `Secure Text — описание Android-проекта.md` §29
> (модель угроз) и §34–§35 (требования безопасности).

---

## 1. Модель угроз

### 1.1. Защищаемся от

| Угроза | Защита |
|---|---|
| Чтение сообщения оператором/сервером мессенджера | XChaCha20-Poly1305 с ключом, известным только endpoints. |
| Модификация сообщения при передаче | AEAD-тег + Ed25519-подпись. Любая мутация детектируется. |
| Подмена публичного ключа получателя (MITM при первом обмене) | Fingerprint verification по независимому каналу; `verified`-флаг; `KEY_CHANGE_WARNING` при смене ключа. |
| Компрометация долгосрочного X25519-ключа получателя | Ephemeral X25519-ключ на каждое сообщение → message-level forward secrecy. |
| Чтение приватного ключа с диска | Argon2id-защита + Android Keystore-обёртка. |
| Чтение памяти другим приложением | Android Keystore (Hardware-backed на поддерживаемых устройствах), FLAG_SECURE на чувствительных экранах. |
| Скриншот чувствительных экранов | FLAG_SECURE блокирует screenshot и screen recording. |
| Утечка plaintext через clipboard | Clipboard timeout + явный контроль, нет автокопирования приватных ключей. |
| Утечка через логи | Запрет на логирование plaintext, ключей, пароля. Только статусы и версии. |
| Network-утечки | Приложение не имеет INTERNET-разрешения. |

### 1.2. Не защищаемся от

| Угроза | Комментарий |
|---|---|
| Полностью скомпрометированный телефон (root с активным malware) | Если атакующий контролирует OS, никакое приложение не поможет. |
| Скриншот уже расшифрованного сообщения, сделанный пользователем | Не наша зона ответственности. |
| Пользователь сам передал пароль или приватный ключ | Социальная инженерия. |
| Утечка через hardware (side-channel на конкретном устройстве) | Митигация: использовать Tink/Android Keystore, прошедшие аудит. |
| Скомпрометированные зависимости (supply chain) | Митигация: pinned versions, reproducible builds, GPG-верификация артефактов. |
| Атака на fingerprint-канал, если MITM может модифицировать и его | Fingerprint — last-line defense, требует независимого канала. |

### 1.3. Out-of-scope для v1

- **Replay protection** — STX2.md §36 явно вне протокола, в v1
  только UI-предупреждение «вы уже видели это сообщение».
- **Ratcheting / continuous forward secrecy** — STX2 не ratcheting
  protocol. Требует отдельного протокола.
- **Metadata** — STX2.md §37: мессенджер знает отправителя, получателя,
  время, размер. Это by design.
- **Большие файлы** — STX2 ограничен ~100 KiB plaintext. Файлы — отдельный
  протокол.

---

## 2. Криптографические гарантии

### 2.1. Конфиденциальность

- XChaCha20-Poly1305 IETF (96-bit nonce, 256-bit key) — IND-CCA2 secure
  при уникальном nonce.
- Nonce 24 случайных байта → коллизия невозможна (192-bit space).
- Ключ 32 байта, вырабатывается через HKDF-SHA256 с `info =
  "SecureText v2 X25519 XChaCha20-Poly1305"`.

### 2.2. Целостность

- Poly1305 AEAD-тег (16 байт) на каждом сообщении.
- Ed25519-подпись (64 байта) поверх `canonical_without_signature(obj)`.
- Покрывает: `v, epk, nonce, ct, sender_ed25519`.
- Не покрывает (by design): `sig` (поле добавляется после подписания).

### 2.3. Аутентификация

- Получатель знает `sender_ed25519` (32 байта) — публичный ключ
  отправителя.
- Ed25519-подпись проверяется **до** расшифровки.
- **Дополнительно:** `sender_ed25519` сверяется с локальной базой
  контактов. Если есть и `verified=true` → пользователь уверен в
  личности отправителя.

### 2.4. Forward secrecy

- На каждое сообщение — новый ephemeral X25519-ключ.
- Компрометация долгосрочного ключа получателя → attacker не может
  расшифровать **прошлые** сообщения, если ephemeral privates были
  уничтожены сразу после использования.
- **Ограничение:** нет ratcheting, нет post-compromise security.
  Компрометация долгосрочного ключа отправителя → attacker может
  подделать **будущие** сообщения от этого отправителя.

### 2.5. Хранение ключей

- Argon2id (time=3, mem=64 MiB, par=2, hash_len=32) — password KDF.
- ChaCha20-Poly1305 IETF (12-байт nonce) — AEAD приватных ключей.
- AAD = `"SecureText private key v2"` — domain separation.
- Salt = 16 случайных байт на каждый приватный ключ.
- KEK оборачивается Android Keystore (AES-GCM, hardware-backed на
  поддерживаемых устройствах).
- Биометрия разблокирует Keystore-ключ → unwrap KEK.

---

## 3. Жизненный цикл секретов

| Секрет | Где хранится | Где используется | Когда уничтожается |
|---|---|---|---|
| Password пользователя | Нигде | Argon2id один раз | Сразу после derive (перезатирается). |
| KEK (после Argon2id) | В памяти + Android Keystore (wrapped) | Decrypt приватных ключей | При блокировке приложения (`onStop` или 15 мин idle). |
| X25519 private | Encrypted в `EncryptedSharedPreferences` (Tink keyset) | При decrypt сообщения | После использования в `SecureBytes.wipe()`. |
| Ed25519 private | Encrypted в `EncryptedSharedPreferences` (Tink keyset) | При encrypt сообщения | После использования в `SecureBytes.wipe()`. |
| Ephemeral X25519 private | Только в памяти | Derive shared secret | Сразу после derive. |
| XChaCha20 nonce | В памяти + в STX2 сообщении | Encrypt один раз | После шифрования. |
| Shared secret | Только в стеке, не сохраняется | HKDF один раз | После derive message_key. |
| Message key (32 B) | Только в стеке | AEAD encrypt/decrypt один раз | После AEAD-операции. |
| Plaintext | UI state, Compose | Отображение пользователю | При `onStop` экрана / уход в background. |

---

## 4. Что **никогда** не делаем

Из промпта и `Secure Text — описание Android-проекта.md` §34:

- ❌ Самостоятельно реализуем криптопримитивы. Только Tink, BouncyCastle
  (для Argon2id через argon2kt) и Android Keystore.
- ❌ Логируем приватные ключи, plaintext, password, shared secret.
- ❌ Отправляем что-либо по сети (нет INTERNET-разрешения).
- ❌ Используем ECB, CBC без MAC, самописные режимы.
- ❌ Переиспользуем nonce с одним ключом.
- ❌ Переиспользуем ephemeral X25519.
- ❌ Отключаем проверку подписи или AEAD-тега.
- ❌ Храним password в любом виде.
- ❌ Помещаем приватные ключи в clipboard.
- ❌ Передаём приватные ключи через Intent extras.
- ❌ Отключаем security-функции ради прохождения тестов.
- ❌ Молча заменяем публичный ключ контакта.

---

## 5. Сетевые разрешения

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

**НЕ добавляется.** Приложение работает полностью offline. Любые
попытки network-вызовов = баг.

(Если в будущем понадобится QR-сканирование через ML Kit on-device —
оно тоже работает offline, INTERNET не нужен.)

---

## 6. Аудит зависимостей

| Зависимость | Проверка |
|---|---|
| `com.google.crypto.tink:tink-android` | Регулярные релизы Google. Fuzz-тесты. Используется в Google Pay, End-to-End. |
| `com.lambdapioneer.argon2kt:argon2kt` | Open source, JNI binding к reference Argon2 implementation. |
| `androidx.biometric:biometric` | Google official. |
| `androidx.security:security-crypto` | Google official. |
| Compose, Hilt, Coroutines | Google official. |

**Pinned versions** — фиксируются в `gradle/libs.versions.toml`.
**Lockfile** — Gradle dependency locking.
**CVE-мониторинг** — Dependabot / GitHub Security Advisories.

---

## 7. UX-уровень безопасности

| Сценарий | Поведение |
|---|---|
| Пользователь нажимает «Скопировать» на зашифрованном сообщении | Скопировать, показать snackbar «Скопировано». Clipboard cleared через 60 с. |
| Пользователь пытается расшифровать без разблокировки | Показать «Разблокировать Secure Text?» → BiometricPrompt. |
| Подпись неверна | Показать «Не удалось проверить сообщение. Оно могло быть изменено.» Plaintext **не показывается**. |
| Отправитель неизвестен | Показать plaintext + warning «Отправитель не в списке контактов». |
| Отправитель есть, но `verified=false` | Показать + warning «Ключ не подтверждён. Сверьте fingerprint с собеседником». |
| Отправитель есть, `verified=true` | Показать + ✓ «Подпись проверена, отправитель подтверждён». |
| Ключ отправителя изменился | `KEY_CHANGE_WARNING` + plaintext показывается с предупреждением, обновление ключа требует явного подтверждения. |
| Попытка открыть контакт → фингерпринт крупно | Экран `FingerprintDisplayScreen`, удобный для сверки по видео/голосом. |
| Биометрия отключена пользователем | Fallback на PIN/пароль устройства (если задан); иначе — отказ с объяснением. |
| Скриншот чувствительного экрана | FLAG_SECURE блокирует. |

---

## 8. Аварийные ситуации

| Ситуация | Поведение |
|---|---|
| Пользователь забыл пароль | **Безвозвратно.** Показать экран «Без пароля восстановить ключ невозможно. Создайте новую идентичность.» |
| Backup-файл повреждён | Показать «Резервная копия повреждена или изменена». |
| Backup-файл с неверным паролем | Показать «Неверный пароль». |
| Устройство не поддерживает StrongBox | Использовать обычный Keystore с предупреждением в логах (не в UI). |
| Устройство не имеет биометрии | Fallback на PIN/пароль устройства (через BiometricPrompt с `BIOMETRIC_WEAK` + `DEVICE_CREDENTIAL`). |
| App uninstall | Все данные стираются (DataStore + Keystore key). |

---

## 9. Соответствие нормативным документам

- [x] `STX2.md` (v2) — спецификация протокола.
- [x] `Secure Text — описание Android-проекта.md` — ТЗ.
- [x] `Промпт_для_OpenCode___разработка_Secure_Text_Android.md` — задание.
- [x] `test_vectors.json` — interop-вектора (5 positive + 7 negative).
- [x] OWASP MASVS-RESILIENCE (частично): device-binding через Keystore,
  anti-tampering через Play Integrity (опционально для v2).
- [x] NIST SP 800-38D (для AES-GCM) — не применимо напрямую, но
  ChaCha20-Poly1305 IETF (RFC 8439) эквивалентен по guarantees.
- [x] RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF),
  RFC 9106 (Argon2), draft-irtf-cfrg-xchacha (XChaCha20-Poly1305).

---

## 10. Известные ограничения v1

1. **Нет QR-кода.** Только текстовый импорт/экспорт.
2. **Нет replay protection.** Планируется в v2.
3. **Нет ratcheting.** Сообщения защищены forward secrecy, но не
   post-compromise security.
4. **Single-device identity.** Multi-device sync — вне v1.
5. **Argon2id 64 MiB** — может быть медленным на старых устройствах
   (~1–2 с). Возможна адаптивная настройка (time/mem) по device profile
   в v2.
6. **Tink keyset файл** хранится в app-private storage, не экспортируется.
   Backup — отдельный защищённый канал.

---

*Дата:* 2026-09-07
*Статус:* Черновик, дополнится по мере реализации.
