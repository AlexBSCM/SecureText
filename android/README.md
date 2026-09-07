# Secure Text — Android

Локальное Android-приложение для E2E-шифрования текстовых сообщений
перед отправкой через любой мессенджер. См. `../README.md`, `../STX2 Protocol Specification.md`,
`../ANALYSIS.md`, `../ARCHITECTURE.md`, `../SECURITY.md` в корне репозитория.

## Стек

- Kotlin 2.0 + Jetpack Compose + Material 3
- minSdk 26, targetSdk/compileSdk 34
- Hilt (DI), Coroutines + StateFlow, Navigation Compose
- Tink + argon2kt (добавятся на Этапе 3)
- Полностью offline — `INTERNET` НЕ запрашивается

## Структура

```
android/
├── app/                          # единственный модуль
│   ├── build.gradle.kts
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/securetext/app/
│   │   │   ├── MainActivity.kt
│   │   │   ├── SecureTextApplication.kt
│   │   │   ├── navigation/      # NavHost + Destinations
│   │   │   ├── ui/
│   │   │   │   ├── theme/        # Material 3 colors
│   │   │   │   ├── common/       # PlaceholderScreen
│   │   │   │   ├── identity/     # My Identity (заглушка)
│   │   │   │   ├── encrypt/      # Encrypt (заглушка)
│   │   │   │   ├── decrypt/      # Decrypt (заглушка)
│   │   │   │   ├── contacts/     # Contacts (заглушка)
│   │   │   │   └── settings/     # Settings (заглушка)
│   │   │   └── (crypto/, protocol/, storage/, contacts/, share/, security/ — добавятся позже)
│   │   └── res/
│   │       ├── values/strings.xml          (en)
│   │       ├── values-ru/strings.xml       (ru)
│   │       ├── values/themes.xml
│   │       ├── xml/data_extraction_rules.xml  (запрет бэкапа)
│   │       ├── drawable/ic_launcher_*
│   │       └── mipmap-anydpi-v26/ic_launcher*
│   └── src/test/                 # JVM unit-тесты
├── build.gradle.kts              # root
├── settings.gradle.kts
├── gradle.properties
├── gradle/
│   ├── libs.versions.toml        # version catalog
│   └── wrapper/                  # gradle-wrapper.jar (создаётся через `gradle wrapper`)
└── README.md
```

## Текущий статус — Этап 2 (skeleton)

- 5 экранов (Identity / Encrypt / Decrypt / Contacts / Settings) с
  единой заглушкой. Bottom navigation работает.
- DI через Hilt подключён, `@HiltAndroidApp` и `@AndroidEntryPoint` стоят.
- Crypto и storage **не реализованы** — это следующие этапы.

## Сборка

Из каталога `android/`:

```bash
gradle wrapper                 # один раз, для генерации gradlew
./gradlew :app:assembleDebug   # debug APK
./gradlew :app:testDebugUnitTest
```

Для Android Studio: `File → Open → android/`, дождаться Gradle Sync,
`Run 'app'`.

## Что будет добавлено

| Этап | Что |
|---|---|
| 3 | `crypto/` — Tink + argon2kt обёртки (X25519, Ed25519, XChaCha20, HKDF, Argon2id) |
| 4 | `protocol/` — STX2 Encryptor, Decryptor, Fingerprint, message parse/serialize |
| 5 | `storage/IdentityStore` — Tink + Android Keystore + Biometric |
| 6 | `contacts/` — verified, firstSeen, history |
| 7 | Реальные экраны Encrypt/Decrypt |
| 8 | Clipboard + Sharesheet + auto-detect `STX2:` |
| 9 | Fingerprint UI |
| 10 | Backup/Restore `.stx` |
| 11 | QR (отложен) |
| 12 | Полное тестирование + Android↔Python interop |
