# Secure Text — Android: ARCHITECTURE.md

> Документ-черновик. Будет дополняться по мере реализации этапов.
> Цель — зафиксировать структуру пакетов и потоки данных до
> начала кодирования.

---

## 0. Технологический стек

| Слой | Технология | Версия |
|---|---|---|
| Язык | Kotlin | 2.0+ |
| UI | Jetpack Compose | BOM 2024.06+ |
| Design | Material 3 | 1.3+ |
| DI | Hilt | 2.51+ |
| Async | Coroutines + StateFlow | 1.8+ |
| Persistence | DataStore Preferences + JSON | 1.1+ |
| Crypto | Google Tink | 1.13+ |
| Argon2id | `com.lambdapioneer.argon2kt:argon2kt` | 1.2+ |
| Biometric | `androidx.biometric:biometric` | 1.2+ |
| minSdk | 26 (Android 8.0) | — |
| targetSdk / compileSdk | 34 (Android 14) | — |
| Build | Gradle 8.7+, AGP 8.5+ | — |

---

## 1. Структура пакетов

```
app/
├── crypto/                           # Tink + argon2kt обёртки
│   ├── primitives/                   # X25519, Ed25519, XChaCha20, HKDF
│   ├── argon2/                       # Argon2id
│   ├── keywrap/                      # Keystore-обёртка KEK
│   └── util/                         # Base64URL, hex, secure random, secure wipe
├── protocol/                         # STX2: parse/serialize/encrypt/decrypt
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

## 2. Слои и поток данных

```
┌─────────────────────────────────────────────────────────────┐
│ UI (Compose, ViewModel)                                      │
│   - принимает ввод                                           │
│   - показывает ошибки и статусы                              │
│   - НЕ выполняет криптографию                                │
└────────────────────────┬────────────────────────────────────┘
                         │ suspend fun
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Use-cases: EncryptText, DecryptText, AddContact, ...         │
│   - оркестрация Encryptor/Decryptor + IdentityStore         │
│   - проверка verified-флага, key-change detection            │
└────────────────────────┬────────────────────────────────────┘
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
┌────────────────┐ ┌────────────┐ ┌──────────────┐
│ protocol/      │ │ crypto/    │ │ storage/     │
│ Encryptor,     │ │ primitives │ │ IdentityStore│
│ Decryptor,     │ │ (Tink)     │ │ ContactStore │
│ Fingerprint    │ └────────────┘ └──────────────┘
└────────────────┘
```

**Запрещено:**
- Compose напрямую вызывает `X25519`, `Ed25519`, `XChaCha20-Poly1305`.
- ViewModel знает про `KeyGenParameterSpec` или `BiometricPrompt`.
- `protocol/` и `crypto/primitives` зависят от `android.*`.

---

## 3. Хранение ключей

### 3.1. Long-term identity

```
X25519 private (32 B)
Ed25519 private (32 B)
        │
        ▼
Argon2id(pw, salt=random 16 B,
         time=3, mem=64 MiB, par=2, hash_len=32)
        │
        ▼
KEK (32 B)
        │
        ▼
ChaCha20-Poly1305(KEK, nonce=random 12 B, AAD="SecureText private key v2")
        │
        ▼
encrypted_x25519_private (48 B)        # 32 + 16 tag
encrypted_ed25519_private (48 B)
```

KEK дополнительно оборачивается Android Keystore-ключом (Tink
`AndroidKeysetManager`): биометрия разблокирует Keystore → unwrap KEK →
ChaCha20-Poly1305 decrypt приватных ключей.

### 3.2. Контакты

Хранятся в `DataStore<Preferences>` как JSON-строка:

```json
{
  "version": 1,
  "contacts": [
    {
      "id": "uuid-v4",
      "name": "Алексей",
      "public_identity": "STX-PUB2:...",
      "x25519_public": "<b64url>",
      "ed25519_public": "<b64url>",
      "fingerprint": "AB12 CD34 ...",
      "verified": true,
      "firstSeenMs": 1700000000000,
      "lastSeenMs":  1720000000000,
      "keyHistory": [
        {"ed25519": "<b64url>", "fingerprint": "...", "validFromMs": ..., "validToMs": 1720000000000}
      ]
    }
  ]
}
```

### 3.3. Backup / Restore

Файл `.stx`:

```json
{
  "version": 2,
  "format": "secure-text-backup-v1",
  "kdf": "Argon2id",
  "kdf_params": {"time": 3, "mem_kib": 65536, "par": 2, "salt": "<b64url-16>"},
  "cipher": "ChaCha20-Poly1305",
  "aad": "SecureText private key v2",
  "nonce": "<b64url-12>",
  "ciphertext": "<b64url-...>",
  "created_at_ms": 1700000000000
}
```

`ciphertext` = X25519 priv (32) + Ed25519 priv (32) + version (1) + reserved (7)
= 72 B + 16 B tag = 88 B.

**Совместимость с Python:** Python `keys.json` имеет другую структуру
(два независимых `{salt, nonce, ciphertext}` блока). Конвертер
`tools/stx_convert.py` — отдельная задача.

---

## 4. Поток шифрования

```
UI.EncryptScreen → ViewModel.encrypt(contactId, text)
  → EncryptTextUseCase.invoke(contactId, text)
      1. ContactRepository.getById(contactId) → Contact
      2. IdentityStore.getX25519Private()      // requires unlocked
         IdentityStore.getEd25519Private()
      3. Protocol.Encryptor.encrypt(plaintext, contact.x25519_pub, sender_ed_priv)
         → STX2 message
      4. return STX2 message
  → UI: показать результат + Copy + Share
```

`Encryptor.encrypt`:

```
1. ephemeral_priv = X25519.generateKey()
2. shared = ephemeral_priv.exchange(recipient_x_pub)
3. message_key = HKDF-SHA256(shared, None, "SecureText v2 X25519 XChaCha20-Poly1305", 32)
4. nonce = SecureRandom(24)
5. ct = XChaCha20-Poly1305.encrypt(message_key, nonce, plaintext_utf8, aad="STX2")
6. obj = {"v":2, "epk": b64(ephemeral_pub), "nonce": b64(nonce),
          "ct": b64(ct), "sender_ed25519": b64(sender_ed_pub)}
7. canonical_unsigned = canonical_json(obj minus sig)
8. sig = Ed25519.sign(sender_ed_priv, canonical_unsigned)
9. obj["sig"] = b64(sig)
10. return "STX2:" + b64(canonical_json(obj))
```

---

## 5. Поток расшифровки

```
UI.DecryptScreen → ViewModel.decrypt(stx2Message)
  → DecryptTextUseCase.invoke(stx2Message)
      1. IdentityStore.getX25519Private()  // requires unlocked
      2. Protocol.Decryptor.decrypt(stx2Message, recipient_x_priv, contactRepo)
         a. parse + validate prefix + version + fields
         b. lookup contact by sender_ed25519 → Contact?
         c. if Contact && sender_ed25519 != Contact.ed25519 → KEY_CHANGE_WARNING
         d. verify Ed25519 signature (mandatory)
         e. shared = recipient_x_priv.exchange(epk)
         f. message_key = HKDF-SHA256(shared, None, ..., 32)
         g. plaintext = XChaCha20-Poly1305.decrypt(message_key, nonce, ct, aad="STX2")
         h. return DecryptionResult(plaintext, sender_key, signatureValid, contactStatus)
  → UI: показать plaintext + статус подписи + статус контакта
```

**Правила отображения:**
- `signatureValid=false` → **НИКОГДА не показывать plaintext**.
- `signatureValid=true && Contact==null` → plaintext + «отправитель не в контактах».
- `signatureValid=true && Contact.verified=false` → plaintext + «ключ не подтверждён».
- `signatureValid=true && Contact.verified=true` → plaintext + «✓».
- `Contact.found && sender_key_changed` → plaintext + «ключ изменился, не доверяйте».

---

## 6. Concurrency и жизненный цикл

- Криптографические операции — CPU-bound → `Dispatchers.Default`.
- I/O — `Dispatchers.IO`.
- IdentityStore кеширует разблокированные приватные ключи в памяти
  (`@Singleton`, автоблокировка при `onStop` или через 15 мин idle).
- При `onStop` экрана Decrypt — очищаем plaintext из state.
- Биометрия — только при доступе к приватным ключам.

---

## 7. Тестирование

### 7.1. Unit-тесты

- `protocol/` — pure JVM, без Android.
- `crypto/primitives`, `crypto/argon2` — pure JVM.
- `crypto/keywrap/` (Keystore) — instrumentation test.

### 7.2. Integration

- Encrypt → Decrypt roundtrip (JVM).
- Encrypt на Python → Decrypt на Android и наоборот (interop).
- Backup → Restore roundtrip.

### 7.3. Negative

- Все из `test_vectors.json` секции `negative_vectors`.
- Дополнительно: пустой plaintext, plaintext ровно 100 KiB, 100 KiB + 1 B.

### 7.4. UI

- Compose UI tests для всех экранов.
- `FLAG_SECURE` — instrumentation-тестом.

---

## 8. Точки расширения (для v2+)

- **QR-код:** добавляется в `ui/identity/` без изменений в `protocol/`.
- **Multi-device sync:** потребует ratcheting. Не входит в v1.
- **File encryption:** отдельный формат. Не входит в v1.
- **Replay protection:** локальный SHA-256(message) кеш в DataStore.

---

## 9. Диаграмма пакетов

```
app
 ├──► ui.identity
 ├──► ui.encrypt
 ├──► ui.decrypt
 ├──► ui.contacts
 ├──► ui.settings
 │
 ├──► domain.usecase.EncryptText
 ├──► domain.usecase.DecryptText
 ├──► domain.usecase.AddContact
 ├──► domain.usecase.VerifyContact
 ├──► domain.usecase.ExportBackup
 ├──► domain.usecase.ImportBackup
 │
 ├──► storage.IdentityStore
 ├──► storage.ContactStore
 ├──► storage.BackupCodec
 ├──► contacts.ContactRepository
 ├──► share.ClipboardHelper
 ├──► share.SharesheetHelper
 ├──► security.BiometricUnlock
 │
 └──► protocol.Encryptor
      protocol.Decryptor
      protocol.Fingerprint
      │
      ├──► crypto.primitives.X25519
      ├──► crypto.primitives.Ed25519
      ├──► crypto.primitives.XChaCha20Poly1305
      ├──► crypto.primitives.HkdfSha256
      ├──► crypto.argon2.Argon2id
      ├──► crypto.fingerprint.Fingerprint
      └──► crypto.util.*
```

---

## 10. Открытые вопросы

- [ ] Безопасный wipe plaintext (`CharArray` + `Arrays.fill(ch, 0)`) — Этап 7.
- [ ] Clipboard timeout: `WorkManager` vs `Handler.postDelayed` — Этап 8.
- [ ] Что делать, если пользователь пытается расшифровать `STX2:...`
      без разблокировки → prompt «Разблокировать Secure Text?».

---

*Дата:* 2026-09-07
*Статус:* Черновик.
