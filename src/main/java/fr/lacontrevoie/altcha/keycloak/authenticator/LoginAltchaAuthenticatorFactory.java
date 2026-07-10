package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class LoginAltchaAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "login-altcha-action";
    private static final LoginAltchaAuthenticator SINGLETON = new LoginAltchaAuthenticator();

    @Override
    public String getId() { return PROVIDER_ID; }

    @Override
    public String getDisplayType() { return "ALTCHA (Login)"; }

    @Override
    public String getHelpText() { return "Protects the login form with an ALTCHA challenge."; }

    @Override
    public String getReferenceCategory() { return "altcha"; }

    @Override
    public boolean isConfigurable() { return true; }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{ Requirement.REQUIRED, Requirement.DISABLED };
    }

    @Override
    public boolean isUserSetupAllowed() { return false; }

    @Override
    public Authenticator create(org.keycloak.models.KeycloakSession session) {
        return SINGLETON;
    }

    @Override public void init(Scope config) {}
    @Override public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {}
    @Override public void close() {}

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return AltchaSupport.CONFIG_PROPERTIES;
    }
}
