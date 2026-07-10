package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.Map;

/**
 * Adds an ALTCHA challenge on top of the standard username/password login form.
 *
 * <p>This class is a singleton shared across all concurrent requests (see
 * {@link LoginAltchaAuthenticatorFactory}), so it holds <b>no instance state</b>.
 * The per-request provider config is passed to the {@link #createLoginForm} hook
 * — which {@link UsernamePasswordForm} calls internally when rendering — through
 * a {@link ThreadLocal}, since a request is bound to a single thread.
 */
public class LoginAltchaAuthenticator extends UsernamePasswordForm {

    private static final ThreadLocal<Map<String, String>> REQUEST_CONFIG = new ThreadLocal<>();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel == null || !AltchaSupport.isConfigured(configModel.getConfig())) {
            context.form().setError(Messages.RECAPTCHA_NOT_CONFIGURED);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createLoginUsernamePassword());
            return;
        }

        REQUEST_CONFIG.set(configModel.getConfig());
        try {
            // Lets UsernamePasswordForm handle username prefill (login hint / remember me)
            // and render via createLoginForm(), where we inject the challenge.
            super.authenticate(context);
        } finally {
            REQUEST_CONFIG.remove();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel == null || !AltchaSupport.isConfigured(configModel.getConfig())) {
            context.form().setError(Messages.RECAPTCHA_NOT_CONFIGURED);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createLoginUsernamePassword());
            return;
        }
        Map<String, String> config = configModel.getConfig();

        REQUEST_CONFIG.set(config);
        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            String captchaResp = formData.getFirst(AltchaSupport.ALTCHA_RESPONSE);

            if (Validation.isBlank(captchaResp)) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        challengeWithError(context, config, "altcha.captchaFormEmpty"));
                return;
            }

            try {
                if (!AltchaSupport.verifySolution(captchaResp, config.get(AltchaSupport.KEY_SECRET))) {
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                            challengeWithError(context, config, "altcha.captchaValidationFailed"));
                    return;
                }
            } catch (Exception e) {
                ServicesLogger.LOGGER.recaptchaFailed(e);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        challengeWithError(context, config, "altcha.captchaValidationException"));
                return;
            }

            // Captcha valid: delegate username/password validation and success/failure
            // handling to the parent. A validation failure re-renders through
            // createLoginForm(), which re-attaches a fresh challenge.
            super.action(context);
        } finally {
            REQUEST_CONFIG.remove();
        }
    }

    /**
     * Injects the challenge whenever {@link UsernamePasswordForm} renders the login
     * form (initial display and password-validation failures), using the config
     * bound to the current request.
     */
    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        Map<String, String> config = REQUEST_CONFIG.get();
        if (config != null) {
            try {
                AltchaSupport.applyChallenge(config, form);
            } catch (Exception e) {
                ServicesLogger.LOGGER.recaptchaFailed(e);
            }
        }
        return super.createLoginForm(form);
    }

    /** Build a fresh username/password form carrying an ALTCHA error and a new challenge. */
    private Response challengeWithError(AuthenticationFlowContext context, Map<String, String> config, String errorKey) {
        LoginFormsProvider form = context.form();
        form.setError(AltchaSupport.ALTCHA_RESPONSE, errorKey);
        try {
            AltchaSupport.applyChallenge(config, form);
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return form.createLoginUsernamePassword();
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
    public void close() {
    }
}
