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

import jakarta.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.List;

public class RegistrationAltcha implements FormAction, FormActionFactory {
    public static final String ALTCHA_RESPONSE = AltchaSupport.ALTCHA_RESPONSE;
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

        if (captchaConfig == null || !AltchaSupport.isConfigured(captchaConfig.getConfig())) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        try {
            AltchaSupport.applyChallenge(captchaConfig.getConfig(), form);
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
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
        if (captchaConfig == null || !AltchaSupport.isConfigured(captchaConfig.getConfig())) {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }
        String hmacKey = captchaConfig.getConfig().get(AltchaSupport.KEY_SECRET);

        try {
            // check if captcha solution is valid
            if (!AltchaSupport.verifySolution(captcha_resp, hmacKey)) {
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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return AltchaSupport.CONFIG_PROPERTIES;
    }

}
