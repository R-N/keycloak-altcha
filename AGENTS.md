# AGENTS.md

Guidance for AI coding agents working in this repository. (Claude Code reads `CLAUDE.md`, which mirrors this file.)

## What this is

Keycloak extension adding [ALTCHA](https://altcha.org/) proof-of-work CAPTCHA to **registration** and **login** flows. Privacy-friendly drop-in for reCAPTCHA/hCaptcha. Challenges are generated server-side via [altcha-lib-java](https://github.com/altcha-org/altcha-lib-java) — **no third-party calls**. Originally based on the hCaptcha extension.

## Build & test

Requires **Java 17** and Maven.

```bash
mvn clean compile package
# pin JDK:
JAVA_HOME=/usr/lib/jvm/java-17-openjdk/ mvn clean compile package
```

Two JARs land in `target/`. The deployable one is `keycloak-altcha-jar-with-dependencies.jar` (fat JAR via maven-assembly-plugin, bundles `altcha` + `org.json`). Deploy by dropping it into `<keycloak>/providers`.

No test suite exists. Verification is manual against a running Keycloak instance.

## Architecture

`AltchaSupport` is the shared, **stateless** core: the single `CONFIG_PROPERTIES` list, safe config parsing (`parsePositiveLong`), challenge generation (`applyChallenge`) and verification (`verifySolution`). Both providers delegate to it — don't duplicate config props or challenge logic.

Two independent Keycloak SPI providers, both taking the same four config properties (`secret` HMAC key, `floating` UI bool, `complexity` rounds, `expires` seconds):

- **Registration** — `RegistrationAltcha` implements both `FormAction` + `FormActionFactory` in one class. Registered via `META-INF/services/org.keycloak.authentication.FormActionFactory`. Provider ID `registration-altcha-action`, display "ALTCHA".
- **Login** — split into factory (`LoginAltchaAuthenticatorFactory`, the registered SPI) + authenticator (`LoginAltchaAuthenticator extends UsernamePasswordForm`). Wraps the username/password form and layers a challenge on top. Registered via `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`. Provider ID `login-altcha-action`, display "ALTCHA (Login)".

**Shared lifecycle** (both providers, via `AltchaSupport`):
1. Build phase — `applyChallenge` runs `Altcha.createChallenge(options)`, serializes fields (`algorithm`, `challenge`, `salt`, `signature`, `maxnumber`) into `altchaPayload`, plus `altchaRequired` + `altchaFloating`. The theme's `<altcha-widget>` reads these.
2. Validate phase — read `altcha` form param, reject if blank, else `verifySolution`.

Error i18n keys returned to forms: `altcha.captchaFormEmpty`, `altcha.captchaValidationFailed`, `altcha.captchaValidationException`. Missing-config uses Keycloak's `Messages.RECAPTCHA_NOT_CONFIGURED`.

`jboss-deployment-structure.xml` declares the `keycloak-services` module dependency for the fat JAR.

### Gotchas

- **`LoginAltchaAuthenticator` must stay stateless** — the factory returns a shared singleton, so per-request data cannot be instance fields (that caused a concurrency bug). Request config reaches the internal `createLoginForm` render hook via a `ThreadLocal` set in `authenticate`/`action` and cleared in a `finally`.
- `LoginAltchaAuthenticator` extends `UsernamePasswordForm`: captcha-failure re-renders go through `challengeWithError`. Captcha failures use `INVALID_CREDENTIALS` on purpose — avoids a bot-facing oracle.
- **Two separate injection points, both required.** `UsernamePasswordForm.authenticate()`'s initial-render path calls `form.createLoginUsernamePassword()` directly and never calls `createLoginForm()` — so `authenticate()` must call `AltchaSupport.applyChallenge` explicitly on `context.form()` before delegating to `super.authenticate()`. Password-fail re-renders (`action()` → `validateUserAndPassword` → `challenge(context, error, field)`) *do* route through `createLoginForm()`, where the `ThreadLocal`-carried config picks it up. `context.form()` returns the same request-scoped `LoginFormsProvider` instance on every call, so attributes set early survive into later renders. Verified by disassembling `keycloak-services-26.2.5.jar` — don't collapse to a single hook without re-checking.
- Challenge expiry is the `expires` config property (default `AltchaSupport.DEFAULT_EXPIRES = 3600`s). Theme widget `expire` (ms) must be ≥ this.
- i18n is **client-side** (ALTCHAv2 i18n via `altcha-i18n.min.js`), not server-side — server-side i18n was deprecated.

## Theme requirement (operator-side, not in this repo)

The extension only emits form attributes; the operator must edit their login theme to add `<altcha-widget challengejson='${altchaPayload}' ...>` guarded by `<#if altchaRequired??>`, and import `altcha.min.js` + `altcha-i18n.min.js` via `theme.properties` `scripts=`. See `README.md` for the full snippets (registration + login). Vendored JS must be updated by hand for security fixes.

## Versioning

Keycloak version is pinned in `pom.xml` `<version.keycloak>`; bump it and the project `<version>` together when updating. The `altcha` dependency version is independent.
