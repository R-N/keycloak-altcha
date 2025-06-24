package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.ChallengeOptions;
import org.altcha.altcha.Altcha.Challenge;
import org.json.JSONObject;

public class LoginAltchaAuthenticator extends UsernamePasswordForm {

    public static final String ALTCHA_RESPONSE = "altcha";
    public static final long ALTCHA_DEFAULT_EXPIRES = 3600;

    String userLanguageTag;
    AuthenticatorConfigModel config;
    String hmacSecret;
    String floating;
    long complexity;
    ChallengeOptions options;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        applyCaptcha(context, form);
        context.challenge(form.createLoginUsernamePassword());
        super.authenticate(context);
    }
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        LoginFormsProvider form = context.form();  // Call once
    
        String captcha_resp = formData.getFirst(ALTCHA_RESPONSE);
    
        if (Validation.isBlank(captcha_resp)) {
            form.setError("altcha", "altcha.captchaFormEmpty");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, form.createLoginUsernamePassword());
            return;
        }
    
        String hmacKey = context.getAuthenticatorConfig().getConfig().get("secret");
    
        try {
            applyCaptcha(context, form);

            if (!Altcha.verifySolution(captcha_resp, hmacKey, true)) {
                form.setError("altcha", "altcha.captchaValidationFailed");
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, form.createLoginUsernamePassword());
                return;
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
            form.setError("altcha", "altcha.captchaValidationException");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, form.createLoginUsernamePassword());
            return;
        }
    
        if (!super.validateForm(context, formData)) {
            return;
        }
    
        context.success();
    }


	private boolean loadConfig(AuthenticationFlowContext context){
		if (context == null){
			return false;
		}

        userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        config = context.getAuthenticatorConfig();

        if (config == null || config.getConfig() == null || config.getConfig().get("secret") == null) {
            context.form().setError(Messages.RECAPTCHA_NOT_CONFIGURED);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, context.form().createLoginUsernamePassword());
            return false;
        }

        hmacSecret = config.getConfig().get("secret");
        floating = config.getConfig().get("floating");
        String sComplexity = config.getConfig().get("complexity");
        if (sComplexity == null || sComplexity.trim().isEmpty()){
            sComplexity = "1000000";
        }
        complexity = Long.parseLong(sComplexity);

        options = new ChallengeOptions()
                .setMaxNumber(complexity)
                .setHmacKey(hmacSecret)
                .setExpiresInSeconds(ALTCHA_DEFAULT_EXPIRES);
        config = context.getAuthenticatorConfig();
        
        return true;
	}
    
	private LoginFormsProvider applyCaptcha(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        return applyCaptcha(context, form);
    }
    
    private LoginFormsProvider applyCaptcha(LoginFormsProvider form) {
        return applyCaptcha(null, form);
    }
    
    private LoginFormsProvider applyCaptcha(AuthenticationFlowContext context, LoginFormsProvider form) {
        loadConfig(context);

        try{
            Challenge challenge = Altcha.createChallenge(options);
            JSONObject jsonPayload = new JSONObject();
            jsonPayload.put("algorithm", challenge.algorithm);
            jsonPayload.put("challenge", challenge.challenge);
            jsonPayload.put("salt", challenge.salt);
            jsonPayload.put("signature", challenge.signature);
            jsonPayload.put("maxnumber", options.maxNumber);
    
            form.setAttribute("altchaPayload", jsonPayload.toString());
        }catch(Exception ex){
            throw new RuntimeException(ex.getMessage());
        }
        
        form.setAttribute("altchaRequired", true);
        form.setAttribute("altchaFloating", floating);

        return form;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        applyCaptcha(form);
        return super.createLoginForm(form);
    }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {}
    @Override public void close() {}
}
