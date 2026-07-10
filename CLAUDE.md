# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Keycloak extension adding [ALTCHA](https://altcha.org/) proof-of-work CAPTCHA to **registration** and **login** flows. Privacy-friendly drop-in for reCAPTCHA/hCaptcha. Generates challenges server-side via [altcha-lib-java](https://github.com/altcha-org/altcha-lib-java) — **no third-party calls**. Based originally on the hCaptcha extension.

## Build

Requires **Java 17** and Maven.

```bash
mvn clean compile package
# pin JDK:
JAVA_HOME=/usr/lib/jvm/java-17-openjdk/ mvn clean compile package
```

Two JARs land in `target/`. The deployable one is `keycloak-altcha-jar-with-dependencies.jar` (fat JAR via maven-assembly-plugin, includes `altcha` + `org.json`). Deploy by dropping it into `<keycloak>/providers`.

No test suite exists.

## Architecture

`AltchaSupport` (`AltchaSupport.java`) is the shared, **stateless** core: the single `CONFIG_PROPERTIES` list, safe config parsing (`parsePositiveLong`), challenge generation (`applyChallenge`) and verification (`verifySolution`). Both providers delegate to it — do not duplicate config props or challenge logic in the providers.

Two independent Keycloak SPI providers, both configured with the same four properties (`secret` HMAC key, `floating` UI bool, `complexity` rounds, `expires` seconds):

- **Registration** — `RegistrationAltcha` implements both `FormAction` + `FormActionFactory` in one class. Plugs into the registration form flow. Registered via `META-INF/services/org.keycloak.authentication.FormActionFactory`. Provider ID `registration-altcha-action`, display "ALTCHA".
- **Login** — split into factory (`LoginAltchaAuthenticatorFactory`, the registered SPI) + authenticator (`LoginAltchaAuthenticator extends UsernamePasswordForm`). Wraps username/password form, adds challenge on top. Registered via `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`. Provider ID `login-altcha-action`, display "ALTCHA (Login)".

**Shared lifecycle pattern** (both providers, via `AltchaSupport`):
1. Build phase — `applyChallenge` runs `Altcha.createChallenge(options)`, serializes fields (`algorithm`, `challenge`, `salt`, `signature`, `maxnumber`) into a JSON string set as form attribute `altchaPayload`, plus `altchaRequired` + `altchaFloating`. The `<altcha-widget>` in the theme reads these.
2. Validate phase — read `altcha` form param, reject if blank, else `verifySolution`.

Error i18n keys returned to forms: `altcha.captchaFormEmpty`, `altcha.captchaValidationFailed`, `altcha.captchaValidationException`. Missing-config uses Keycloak's `Messages.RECAPTCHA_NOT_CONFIGURED`.

`jboss-deployment-structure.xml` declares the `keycloak-services` module dependency for the fat JAR.

### Gotchas

- **`LoginAltchaAuthenticator` must stay stateless** — the factory returns a shared singleton, so per-request data cannot be instance fields (that caused a concurrency bug). Request config reaches the internal `createLoginForm` render hook via a `ThreadLocal` set in `authenticate`/`action` and cleared in a `finally`. Keep it that way.
- `LoginAltchaAuthenticator` extends `UsernamePasswordForm`: its own captcha-failure re-renders go through `challengeWithError`. Captcha failures use `INVALID_CREDENTIALS` on purpose — avoids a bot-facing oracle distinguishing captcha vs password.
- **Two separate injection points, both required.** `UsernamePasswordForm.authenticate()`'s initial-render path calls `form.createLoginUsernamePassword()` directly and never calls `createLoginForm()` — so `authenticate()` must call `AltchaSupport.applyChallenge` explicitly on `context.form()` before delegating to `super.authenticate()`. Password-validation-failure re-renders (`action()` → `validateUserAndPassword` → `challenge(context, error, field)`) *do* route through `createLoginForm()`, which is where the `ThreadLocal`-carried config picks it up. `context.form()` returns the same request-scoped `LoginFormsProvider` instance on every call, so attributes set early survive into later renders within the same request. Don't collapse this back to a single hook without re-checking the Keycloak bytecode — it was verified by disassembling `keycloak-services-26.2.5.jar`.
- Challenge expiry is the `expires` config property (default `AltchaSupport.DEFAULT_EXPIRES = 3600`s). Theme widget `expire` (milliseconds) must be ≥ this.
- i18n is **client-side** (ALTCHAv2 i18n system via `altcha-i18n.min.js`), not server-side — server-side i18n was deprecated (commit 57166b7).

## Theme requirement (not in this repo)

The extension only emits form attributes; the operator must edit their login theme (`login/register.ftl` for registration, login template for login) to add `<altcha-widget challengejson='${altchaPayload}' ...>` guarded by `<#if altchaRequired??>`, and import `altcha.min.js` + `altcha-i18n.min.js` via `theme.properties` `scripts=`. See README for the full snippet. These JS files are vendored manually by the operator and must be updated by hand for security fixes.

## Versioning

Keycloak version pinned in `pom.xml` `<version.keycloak>` (currently 26.2.5); bump it and the project `<version>` together when updating. `altcha` dep version is separate.
