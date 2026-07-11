package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.altcha.altcha.v2.Altcha;

/**
 * Shared, stateless helpers for the registration and login ALTCHA providers:
 * the common config-property list, safe config parsing, challenge generation,
 * solution verification and replay-attack detection. Holds no per-request
 * state (the replay cache is a shared concurrent set, safe to call
 * concurrently from singleton authenticators).
 */
public final class AltchaSupport {

    public static final String ALTCHA_RESPONSE = "altcha";
    public static final String ALGORITHM = "PBKDF2/SHA-256";

    public static final String KEY_SECRET = "secret";
    public static final String KEY_EXPIRE_DELAY = "expireDelay";
    public static final String KEY_COMPLEXITY = "complexity";
    public static final String KEY_DISPLAY = "display";
    public static final String KEY_HIDE_FOOTER = "hideFooter";
    public static final String KEY_AUTO = "auto";
    public static final String KEY_MIN_DURATION = "minDuration";

    public static final long DEFAULT_EXPIRE_DELAY = 3600L;
    public static final long DEFAULT_COMPLEXITY = 1_000_000L;
    public static final long DEFAULT_MIN_DURATION = 500L;

    public static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    private static final Set<String> SEEN_SIGNATURES = java.util.concurrent.ConcurrentHashMap.newKeySet();

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(KEY_SECRET);
        property.setLabel("ALTCHA HMAC Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("HMAC secret key - a long random string should be enough.");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_EXPIRE_DELAY);
        property.setLabel("Expiration delay");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("For how many seconds a captcha challenge is valid. Defaults to 3600.");
        property.setDefaultValue(DEFAULT_EXPIRE_DELAY);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_COMPLEXITY);
        property.setLabel("Complexity");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("Captcha complexity (or cost); see ALTCHA docs. Should usually be comprised between 50 000 and 500 000. Defaults to 1000000. Write it without spaces.");
        property.setRequired(true);
        property.setDefaultValue(DEFAULT_COMPLEXITY);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_DISPLAY);
        property.setLabel("Display mode");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(Arrays.asList("standard", "bar", "floating", "overlay", "invisible"));
        property.setHelpText("UI setting, default is 'standard'. See ALTCHA docs.");
        property.setDefaultValue("standard");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_HIDE_FOOTER);
        property.setLabel("Hide the ALTCHA footer");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("UI setting. Hides the ALTCHA footer. Defaults to false.");
        property.setDefaultValue(Boolean.FALSE.toString());
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_AUTO);
        property.setLabel("Automated verification");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(Arrays.asList("off", "onfocus", "onload", "onsubmit"));
        property.setHelpText("Solves the challenge automatically. Default is 'off'.");
        property.setDefaultValue("off");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_MIN_DURATION);
        property.setLabel("Minimal duration");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("Default is 500. See ALTCHA docs.");
        property.setDefaultValue(DEFAULT_MIN_DURATION);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
    }

    private AltchaSupport() {
    }

    /** Parse a positive long from config, falling back to {@code def} on null/blank/invalid/non-positive input. */
    public static long parsePositiveLong(String value, long def) {
        if (value == null || value.trim().isEmpty()) {
            return def;
        }
        try {
            long parsed = Long.parseLong(value.trim());
            return parsed > 0 ? parsed : def;
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /**
     * Generate a fresh challenge from the given provider config and attach the
     * widget attributes ({@code altchaPayload}, {@code altchaRequired},
     * {@code altchaDisplay}, {@code altchaMinDuration}, {@code altchaHideFooter},
     * {@code altchaAuto}) to the form. Caller must ensure the secret is set.
     */
    public static void applyChallenge(Map<String, String> config, LoginFormsProvider form) throws Exception {
        String secret = config.get(KEY_SECRET);
        long complexity = parsePositiveLong(config.get(KEY_COMPLEXITY), DEFAULT_COMPLEXITY);
        long expireDelay = parsePositiveLong(config.get(KEY_EXPIRE_DELAY), DEFAULT_EXPIRE_DELAY);
        long minDuration = parsePositiveLong(config.get(KEY_MIN_DURATION), DEFAULT_MIN_DURATION);

        Altcha.CreateChallengeOptions options = new Altcha.CreateChallengeOptions()
                .algorithm(ALGORITHM)
                .cost((int) complexity)
                .hmacSignatureSecret(secret)
                .expiresInSeconds(expireDelay);

        Altcha.Challenge challenge = Altcha.createChallenge(options);

        boolean hideFooter = Boolean.parseBoolean(config.get(KEY_HIDE_FOOTER));

        form.setAttribute("altchaPayload", challenge.toJson());
        form.setAttribute("altchaRequired", true);
        form.setAttribute("altchaDisplay", config.get(KEY_DISPLAY));
        form.setAttribute("altchaMinDuration", minDuration);
        form.setAttribute("altchaHideFooter", Boolean.toString(hideFooter));
        form.setAttribute("altchaAuto", config.get(KEY_AUTO));
    }

    /** Verify a submitted solution against the HMAC key. */
    public static boolean verifySolution(String response, String hmacKey) throws Exception {
        Altcha.VerifySolutionResult result = Altcha.verifySolution(response, hmacKey, Altcha.kdf(ALGORITHM));
        return result.verified();
    }

    /**
     * True if this is the first time this challenge's signature has been seen
     * (i.e. not a replay). Must only be called after {@link #verifySolution}
     * has confirmed the response is validly signed.
     */
    public static boolean registerSolutionOnce(String response) throws Exception {
        String signature = Altcha.parsePayload(response).challenge().signature();
        return SEEN_SIGNATURES.add(signature);
    }

    /** True when the provider has a usable config (non-blank secret). */
    public static boolean isConfigured(Map<String, String> config) {
        if (config == null) {
            return false;
        }
        String secret = config.get(KEY_SECRET);
        return secret != null && !secret.trim().isEmpty();
    }
}
