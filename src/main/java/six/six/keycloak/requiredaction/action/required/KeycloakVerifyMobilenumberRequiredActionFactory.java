package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Mobile Number verifier (RequireAction)
 * Created by Ashok Kumar <ashok@parserlabs.com> on 10/02/2020.
 */
public class KeycloakVerifyMobilenumberRequiredActionFactory implements RequiredActionFactory {
    private static Logger logger = Logger.getLogger(KeycloakVerifyMobilenumberRequiredActionFactory.class);
    private static final KeycloakVerifyMobilenumberRequiredAction SINGLETON = new KeycloakVerifyMobilenumberRequiredAction();

    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    public String getId() {
        return KeycloakVerifyMobilenumberRequiredAction.PROVIDER_ID;
    }

    public String getDisplayText() {
        return "Verify Mobile Number(s)";
    }

    public void init(Config.Scope config) {
    }

    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }
}
