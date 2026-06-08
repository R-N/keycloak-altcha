package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import org.json.JSONObject;

import jakarta.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import org.altcha.altcha.v2.Altcha;

public class RegistrationAltcha implements FormAction, FormActionFactory {
    public static final String ALTCHA_RESPONSE = "altcha";
    public static final String ALTCHA_REFERENCE_CATEGORY = "altcha";

    public static final String PROVIDER_ID = "registration-altcha-action";

    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "ALTCHA";
    }

    @Override
    public String getReferenceCategory() {
        return ALTCHA_REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Adds ALTCHA button.  ALTCHA verify that the entity that is registering is a human. It must be configured after you add it.";
    }


    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get("secret") == null
                ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        // retrieve ALTCHA settings
        String hmacSecret = captchaConfig.getConfig().get("secret");
        int expireDelay = Integer.parseInt(captchaConfig.getConfig().get("expireDelay"));
        int complexity = Integer.parseInt(captchaConfig.getConfig().get("complexity"));

        // create challenge
        var options = new Altcha.CreateChallengeOptions()
            .algorithm("PBKDF2/SHA-256")
            .cost(complexity)
            .hmacSignatureSecret(hmacSecret)
            .expiresInSeconds(expireDelay);

        // create payload
        try {
            Altcha.Challenge challenge = Altcha.createChallenge(options);

            form.setAttribute("altchaPayload", challenge.toJson());

        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }

        String minDuration = captchaConfig.getConfig().get("minDuration");
        Boolean hideFooter = Boolean.parseBoolean(captchaConfig.getConfig().get("hideFooter"));
        String auto = captchaConfig.getConfig().get("auto");
        String display = captchaConfig.getConfig().get("display");

        form.setAttribute("altchaRequired", true);
        form.setAttribute("altchaDisplay", display);
        form.setAttribute("altchaMinDuration", minDuration);
        form.setAttribute("altchaHideFooter", hideFooter.toString());
        form.setAttribute("altchaAuto", auto);
        form.setAttribute("altchaAuto", auto);
    }

    @Override
    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha_resp = formData.getFirst(ALTCHA_RESPONSE);

        // early return is form data does not contain captcha response
        if (Validation.isBlank(captcha_resp)) {
            errors.add(new FormMessage("altcha.captchaFormEmpty"));
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }

        // retrieve HMAC key
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String hmacKey = captchaConfig.getConfig().get("secret");

        try {
            // check if captcha solution is valid
            Altcha.VerifySolutionResult result = Altcha.verifySolution(captcha_resp, hmacKey, Altcha.kdf("PBKDF2/SHA-256"));
            if (!result.verified()) {
                errors.add(new FormMessage("altcha.captchaValidationFailed"));
            }

        } catch (Exception e) {
            errors.add(new FormMessage("altcha.captchaValidationException"));
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }

        // early return if captcha verification failed. can happen e.g. in case of timeout
        if (!errors.isEmpty()) {
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }

        context.success();
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        
        property = new ProviderConfigProperty();
        property.setName("secret");
        property.setLabel("ALTCHA HMAC Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("HMAC secret key - a long random string should be enough");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("expireDelay");
        property.setLabel("Expiration delay");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("For how many seconds a captcha challenge is valid. Defaults to 3600.");
        property.setDefaultValue(3600);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("complexity");
        property.setLabel("Complexity");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("Captcha complexity (or cost); see ALTCHA docs. Should usually be comprised between 50 000 and 500 000. Defaults to 100 000. Write it without spaces.");
        property.setRequired(true);
        property.setDefaultValue(1000000);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("display");
        property.setLabel("Display mode");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        List<String> display_options = Arrays.asList("standard", "bar", "floating", "overlay", "invisible");
        property.setOptions(display_options);
        property.setHelpText("UI setting, default is 'standard'. See ALTCHA docs.");
        property.setDefaultValue("standard");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("hideFooter");
        property.setLabel("Hide the ALTCHA footer");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("UI setting. Hides the ALTCHA footer. Defaults to false.");
        property.setDefaultValue(Boolean.FALSE.toString());
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("auto");
        property.setLabel("Automated verification");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        List<String> auto_options = Arrays.asList("off", "onfocus", "onload", "onsubmit");
        property.setOptions(auto_options);
        property.setHelpText("Solves the challenge automatically. Default is 'off'.");
        property.setDefaultValue("off");
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("minDuration");
        property.setLabel("Minimal duration");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("Default is 500. See ALTCHA docs.");
        property.setDefaultValue(500);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);
        
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

}
