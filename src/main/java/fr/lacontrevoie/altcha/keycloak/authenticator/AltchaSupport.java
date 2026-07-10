package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.provider.ProviderConfigProperty;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.ChallengeOptions;
import org.altcha.altcha.Altcha.Challenge;

/**
 * Shared, stateless helpers for the registration and login ALTCHA providers:
 * the common config-property list, safe config parsing, challenge generation
 * and solution verification. Holds no per-request state, so it is safe to call
 * concurrently from singleton authenticators.
 */
public final class AltchaSupport {

    public static final String ALTCHA_RESPONSE = "altcha";

    public static final String KEY_SECRET = "secret";
    public static final String KEY_FLOATING = "floating";
    public static final String KEY_COMPLEXITY = "complexity";
    public static final String KEY_EXPIRES = "expires";

    public static final long DEFAULT_COMPLEXITY = 1_000_000L;
    public static final long DEFAULT_EXPIRES = 3600L;

    public static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(KEY_SECRET);
        property.setLabel("ALTCHA HMAC Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("HMAC secret key - a long random string should be enough.");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_FLOATING);
        property.setLabel("ALTCHA Floating UI");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Enables the floating widget UI; see ALTCHA documentation. Warning: the UI may need styling.");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_COMPLEXITY);
        property.setLabel("Complexity");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Captcha complexity (max number of rounds); see ALTCHA docs. 1000000 is a good value.");
        property.setDefaultValue(Long.toString(DEFAULT_COMPLEXITY));
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(KEY_EXPIRES);
        property.setLabel("Challenge expiry (seconds)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("How long a generated challenge stays valid, in seconds. Default 3600. "
                + "Keep your theme widget's expire (in milliseconds) at least this long.");
        property.setDefaultValue(Long.toString(DEFAULT_EXPIRES));
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
     * {@code altchaFloating}) to the form. Caller must ensure the secret is set.
     */
    public static void applyChallenge(Map<String, String> config, LoginFormsProvider form) throws Exception {
        String secret = config.get(KEY_SECRET);
        long complexity = parsePositiveLong(config.get(KEY_COMPLEXITY), DEFAULT_COMPLEXITY);
        long expires = parsePositiveLong(config.get(KEY_EXPIRES), DEFAULT_EXPIRES);

        ChallengeOptions options = new ChallengeOptions()
                .setMaxNumber(complexity)
                .setHmacKey(secret)
                .setExpiresInSeconds(expires);

        Challenge challenge = Altcha.createChallenge(options);

        JSONObject payload = new JSONObject();
        payload.put("algorithm", challenge.algorithm);
        payload.put("challenge", challenge.challenge);
        payload.put("salt", challenge.salt);
        payload.put("signature", challenge.signature);
        payload.put("maxnumber", options.maxNumber);

        form.setAttribute("altchaPayload", payload.toString());
        form.setAttribute("altchaRequired", true);
        form.setAttribute("altchaFloating", config.get(KEY_FLOATING));
    }

    /** Verify a submitted solution against the HMAC key, checking expiry. */
    public static boolean verifySolution(String response, String hmacKey) throws Exception {
        return Altcha.verifySolution(response, hmacKey, true);
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
