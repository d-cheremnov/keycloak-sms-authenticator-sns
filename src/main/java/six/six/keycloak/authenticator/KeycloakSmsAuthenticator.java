package six.six.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.authenticators.challenge.BasicAuthAuthenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import six.six.keycloak.KeycloakSmsConstants;
import six.six.keycloak.MobileNumberHelper;
import six.six.keycloak.authenticator.credential.KeycloakSmsAuthenticatorCredentialProvider;
import six.six.keycloak.requiredaction.action.required.KeycloakSmsMobilenumberRequiredAction;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.List;

/**
 * Created by joris on 11/11/2016.
 */
public class KeycloakSmsAuthenticator extends BasicAuthAuthenticator implements Authenticator, CredentialValidator<KeycloakSmsAuthenticatorCredentialProvider> {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "sms_validation";

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }


    private boolean isOnlyForVerificationMode(boolean onlyForVerification,String mobileNumber,String mobileNumberVerified){
        return (mobileNumber ==null || onlyForVerification==true && !mobileNumber.equals(mobileNumberVerified) );
    }

    private String getMobileNumber(UserModel user){
        return MobileNumberHelper.getMobileNumber(user);
    }

    private String getMobileNumberVerified(UserModel user){
        List<String> mobileNumberVerifieds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED);

        String mobileNumberVerified = null;
        if (mobileNumberVerifieds != null && !mobileNumberVerifieds.isEmpty()) {
            mobileNumberVerified = mobileNumberVerifieds.get(0);
        }
        return  mobileNumberVerified;
    }
    
	private boolean sendSmsCode(AuthenticationFlowContext context, String mobileNumber) {
		long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsConstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
		long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(context.getAuthenticatorConfig(),
				KeycloakSmsConstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

		String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);

		logger.debug("Generated SMSCode with " + nrOfDigits + " digits with ttl " + ttl + " (s)");

		storeSMSCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
		return KeycloakSmsAuthenticatorUtil.sendSmsCode(mobileNumber, code, context);
	}

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate called ... context = " + context);
        UserModel user = context.getUser();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        boolean onlyForVerification=KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED);

        String mobileNumber =getMobileNumber(user);
        String mobileNumberVerified = getMobileNumberVerified(user);

        if (onlyForVerification==false || isOnlyForVerificationMode(onlyForVerification, mobileNumber,mobileNumberVerified)){
            if (mobileNumber != null) {
                // The mobile number is configured --> send an SMS
               
                if (sendSmsCode(context, mobileNumber)) {
                    Response challenge = context.form().createForm("sms-validation.ftl");
                    context.challenge(challenge);
                } else {
                    Response challenge = context.form()
                            .setError("sms-auth.not.send")
                            .createForm("sms-validation-error.ftl");
                    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                }
            } else {
                boolean isAskingFor=KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_ASKFOR_ENABLED);
                if(isAskingFor){
                    //Enable access and ask for mobilenumber
                    user.addRequiredAction(KeycloakSmsMobilenumberRequiredAction.PROVIDER_ID);
                    context.success();
                }else {
                    // The mobile number is NOT configured --> complain
                    Response challenge = context.form()
                            .setError("sms-auth.not.mobile")
                            .createForm("sms-validation-error.ftl");
                    context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
                }
            }
        }else{
            logger.debug("Skip SMS code because onlyForVerification " + onlyForVerification + " or  mobileNumber==mobileNumberVerified");
            context.success();

        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);
        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                challenge = context.form()
                        .setError("sms-auth.code.expired")
                        .createForm("sms-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;

            case INVALID:
                if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.CONDITIONAL ||
                        context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.debug("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    challenge = context.form()
                            .setError("sms-auth.code.invalid")
                            .createForm("sms-validation.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    // Something strange happened
                    logger.warn("Undefined execution ...");
                }
                break;

            case VALID:
                context.success();
                updateVerifiedMobilenumber(context);
                break;

        }
    }

    /**
     * If necessary update verified mobilenumber
     * @param context
     */
    private void updateVerifiedMobilenumber(AuthenticationFlowContext context){
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        UserModel user = context.getUser();
        boolean onlyForVerification=KeycloakSmsAuthenticatorUtil.getConfigBoolean(config, KeycloakSmsConstants.MOBILE_VERIFICATION_ENABLED);

        if(onlyForVerification){
            //Only verification mode
            List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
            if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
                user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED,mobileNumberCreds);
            }
        }
    }
    
    private List<CredentialModel> getStoredCredentialsByType(AuthenticationFlowContext context, String type){
    	return userCredentialManager(context).getStoredCredentialsByType(context.getRealm(), context.getUser(),type);
    }
    
    private UserCredentialManager userCredentialManager(AuthenticationFlowContext context) {
    	return context.getSession().userCredentialManager();
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(AuthenticationFlowContext context, String code, Long expiringAt) {

    	List<CredentialModel> codeCreds = getStoredCredentialsByType(context, KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        List<CredentialModel> timeCreds = getStoredCredentialsByType(context, KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
        CredentialModel codeCredentials, timeCredentials;
    
		if (codeCreds.isEmpty()) {
			codeCredentials = new CredentialModel();
			timeCredentials = new CredentialModel();

			codeCredentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
			codeCredentials.setCredentialData(code);

			userCredentialManager(context).createCredential(context.getRealm(), context.getUser(), codeCredentials);

			timeCredentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
			timeCredentials.setCredentialData(code);
			timeCredentials.setSecretData((expiringAt).toString());
			context.getSession().userCredentialManager().createCredential(context.getRealm(), context.getUser(),
					timeCredentials);
		} else {
			codeCredentials = codeCreds.get(0);
			timeCredentials = timeCreds.get(0);
			codeCredentials.setCredentialData(code);
			userCredentialManager(context).updateCredential(context.getRealm(), context.getUser(), codeCredentials);

			timeCredentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
			timeCredentials.setCredentialData(code);
			timeCredentials.setSecretData((expiringAt).toString());
			userCredentialManager(context).updateCredential(context.getRealm(), context.getUser(), timeCredentials);
		}
    }


    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(KeycloakSmsConstants.ANSW_SMS_CODE);

        List<CredentialModel> codeCreds = getStoredCredentialsByType(context, KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        List<CredentialModel> timeCreds = getStoredCredentialsByType(context, KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);

        CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);
        CredentialModel expTimeString = (CredentialModel) timeCreds.get(0);

        logger.debug("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode.getCredentialData()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            long now = new Date().getTime();

            logger.debug("Valid code expires in " + (Long.parseLong(expTimeString.getSecretData()) - now) + " ms");
            if (result == CODE_STATUS.VALID) {
                if (Long.parseLong(expTimeString.getSecretData()) < now) {
                    logger.debug("Code is expired !!");
                    result = CODE_STATUS.EXPIRED;
                }
            }
        }
        logger.debug("result : " + result);
        return result;
    }
    @Override
    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return true;
    }
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(KeycloakSmsMobilenumberRequiredAction.PROVIDER_ID);
    }
    @Override
    public void close() {
        logger.debug("close called ...");
    }

	@Override
	public KeycloakSmsAuthenticatorCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (KeycloakSmsAuthenticatorCredentialProvider)session.getProvider(CredentialProvider.class, "smsCode");
	}

}
