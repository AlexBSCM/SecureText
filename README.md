# Secure Text

Локальное end-to-end шифрование текстовых сообщений для передачи через
любой мессенджер (Telegram, WhatsApp, Signal, Email, SMS, QR и т.д.).

Принцип: мессенджер — только транспорт. Секретный текст существует в
открытом виде только на устройствах отправителя и получателя.

## Текущая цель

Разработка **Android-приложения** на базе протокола **STX2 v2** (см.
`STX2 Protocol Specification.md`). Python-референс (`secure_text_2.py`)
используется только для interop-тестов.

## Документация

| Файл | Назначение |
|---|---|
| `STX2 Protocol Specification.md` | Нормативная спецификация протокола |
| `Secure Text — описание Android-проекта.md` | Полное ТЗ (UX, модель угроз) |
| `Промпт_для_OpenCode___разработка_Secure_Text_Android.md` | Задание на разработку |
| `ANALYSIS.md` | Анализ папки, нормативные решения, расхождения, риски |
| `STX2_COMPLIANCE_CHECK.md` | Чек-поинт соответствия Python↔STX2 |
| `ARCHITECTURE.md` | Архитектура Android-приложения |
| `SECURITY.md` | Модель угроз, жизненный цикл секретов, запреты |
| `test_vectors.json` | Детерминированные тестовые векторы (5 + 7) |
| `android/README.md` | Сборка, структура, статус |

## Структура

```
Secure Text/
├── secure_text_2.py             # Python-референс (Windows)
├── STX2 Protocol Specification.md
├── Secure Text — описание Android-проекта.md
├── Промпт_для_OpenCode___разработка_Secure_Text_Android.md
├── ANALYSIS.md
├── STX2_COMPLIANCE_CHECK.md
├── ARCHITECTURE.md
├── SECURITY.md
├── test_vectors.json
├── android/                     # Android-приложение (Этап 2 — skeleton)
│   ├── app/
│   ├── build.gradle.kts
│   ├── settings.gradle.kts
│   ├── gradle/libs.versions.toml
│   └── README.md
└── tools/                       # скрипты interop-тестов (Этап 12)
```

## Статус

- **Этап 1** ✅ Анализ, документация, тест-вектора, чек-поинт Python↔STX2.
- **Этап 2** ✅ Gradle skeleton, Compose, 5 экранов-заглушек, навигация, Hilt.
- **Этап 3** ✅ crypto-слой (BouncyCastle `bcprov-jdk18on`: X25519, Ed25519, XChaCha20-Poly1305, HKDF-SHA256, Argon2id) — примитивы + `Stx2Message` + тесты по `test_vectors.json`.
- **Этап 4** ✅ STX2 protocol (`protocol/`: Stx2Message кодек, Encryptor, Decryptor с типизированными исходами, Stx2PublicIdentity, Stx2Fingerprint, Stx2Detector).
- **Этап 5** ✅ Хранение ключей + Biometric (IdentityStore, Keystore-wrapped KEK, CreatePassword/Unlock UI).
- **Этап 6** ⏳ Контакты (verified, history).
- **Этап 7** ⏳ Encrypt/Decrypt UI.
- **Этап 8** ⏳ Clipboard + Share.
- **Этап 9** ⏳ Fingerprint UI.
- **Этап 10** ⏳ Backup/Restore.
- **Этап 11** ⏸ QR (отложен).
- **Этап 12** ⏳ Тесты + Android↔Python interop.
