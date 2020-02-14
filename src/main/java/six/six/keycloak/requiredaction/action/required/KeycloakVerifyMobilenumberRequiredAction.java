package six.six.keycloak.requiredaction.action.required;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;
import org.keycloak.theme.Theme;
import org.keycloak.theme.ThemeProvider;

import static six.six.keycloak.KeycloakSmsConstants.*;

import six.six.gateway.ConsoleSmsService;
import six.six.gateway.Gateways;
import six.six.gateway.SMSService;
import six.six.gateway.aws.snsclient.SnsNotificationService;
import six.six.gateway.govuk.notify.NotifySMSService;
import six.six.gateway.lyrasms.LyraSMSService;
import six.six.keycloak.EnvSubstitutor;
import six.six.keycloak.KeycloakSmsConstants;
import static six.six.keycloak.MobileNumberHelper.*;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticatorFactory;
import static six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil.*;

/**
 * Created by Ashok Kumar <ashok@parserlabs.com> on 10/02/2020.
 * This is an action which will be triggered if Mobile number is verified on first login for user.
 */
public class KeycloakVerifyMobilenumberRequiredAction implements RequiredActionProvider {
    private static Logger logger = Logger.getLogger(KeycloakVerifyMobilenumberRequiredAction.class);
    public static final String PROVIDER_ID = "verify_mobile_numbers";

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }
    
    public void evaluateTriggers(RequiredActionContext context) {
    	 logger.debug("Trigger for Mobile Number verification ...");
    	 UserModel user = context.getUser();
    	 
    	 // If any of the number is not verified then add action.
         if(!isMobileNumberVerified(user) || !isAltMobileNumberVerified(user)) {
        	 user.addRequiredAction(PROVIDER_ID);
         }
         
         // Remove required action if both numbers are verified.
         if(isMobileNumberVerified(user) && isAltMobileNumberVerified(user)) {
        	 user.removeRequiredAction(PROVIDER_ID);
         }
    }


    public void requiredActionChallenge(RequiredActionContext context) {
        UserModel user = context.getUser();
        String mobileNumber = getMobileNumber(user);
        String altMobileNumber = getAltMobileNumber(user);
        LoginFormsProvider form = context.form();
        if(!isMobileNumberVerified(user)) {
        	form.setAttribute("mobileNumber", mobileNumber.substring(mobileNumber.length()-4));
        	sendSmsCodeToPrimaryNumber(context, mobileNumber);
        }
        
        if(!isAltMobileNumberVerified(user)) {
        	form.setAttribute("altMobileNumber", altMobileNumber.substring(altMobileNumber.length()-4));
        	sendSmsCodeToAlternateNumber(context, altMobileNumber);
        }
        
        Response challenge = form.createForm("mobile_verification.ftl");
        context.challenge(challenge);
    }
    
    private static void sendSmsCodeToPrimaryNumber(RequiredActionContext context, String mobileNumber) {
    	logger.debug("Sending OTP to Primary Number: " + mobileNumber);
    	storeAndSendOtp(context, mobileNumber, USR_CRED_MDL_SMS_CODE );
	}
    
    private static void sendSmsCodeToAlternateNumber(RequiredActionContext context, String mobileNumber) {
    	logger.debug("Sending OTP to Alternate Number: " + mobileNumber);
		storeAndSendOtp(context, mobileNumber, USR_CRED_MDL_SMS_CODE_ALT);
	}
    
    private static void storeAndSendOtp(RequiredActionContext context, String mobileNumber, String credType) {
        AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias(KeycloakSmsAuthenticatorFactory.PROVIDER_ID);
		long nrOfDigits = getConfigLong(config, CONF_PRP_SMS_CODE_LENGTH, 6L);
		long ttl = getConfigLong(config,  CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s
		long expiresAt = new Date().getTime() + (ttl * 1000);
		String code = getSmsCode(nrOfDigits);
		storeSMSCode(context,code, expiresAt, credType ); // s --> ms
		sendSmsCode(mobileNumber, code, context, config);
	}
    
    private static boolean sendSmsCode(String mobileNumber, String code, RequiredActionContext context, AuthenticatorConfigModel config) {
        // Send an SMS
        logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUsr = EnvSubstitutor.envSubstitutor.replace(config.getConfig().get(KeycloakSmsConstants.CONF_PRP_SMS_CLIENTTOKEN));
        String smsPwd = EnvSubstitutor.envSubstitutor.replace(config.getConfig().get(KeycloakSmsConstants.CONF_PRP_SMS_CLIENTSECRET));
        String gateway = config.getConfig().get(KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY);

        // LyraSMS properties
        String endpoint = EnvSubstitutor.envSubstitutor.replace(config.getConfig().get(KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY_ENDPOINT));
        boolean isProxy = getConfigBoolean(config, KeycloakSmsConstants.PROXY_ENABLED);

        // GOV.UK Notify properties
        String notifyApiKey = System.getenv(KeycloakSmsConstants.NOTIFY_API_KEY);
        String notifyTemplate = System.getenv(KeycloakSmsConstants.NOTIFY_TEMPLATE_ID);

        // Create the SMS message body
        String template = getMessage(context, KeycloakSmsConstants.CONF_PRP_SMS_TEXT);
        String smsText = createMessage(template, code, mobileNumber);
        String defaultPrefix = getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_DEFAULT);
        String defaultCondition = getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_CONDITION);
        String formattedNumber = "";
        boolean result;
        SMSService smsService;
        try {
            Gateways g = Gateways.valueOf(gateway);
            switch(g) {
                case LYRA_SMS:
                    smsService = new LyraSMSService(endpoint,isProxy);
                    break;
                case GOVUK_NOTIFY:
                    smsService = new NotifySMSService(notifyApiKey, notifyTemplate);
                    break;
                case AMAZON_SNS:
                    smsService = new SnsNotificationService();
                default:
                	smsService = new ConsoleSmsService();
            }
            formattedNumber = checkMobileNumber(setDefaultCountryCodeIfZero(mobileNumber, defaultPrefix, defaultCondition));
            result=smsService.send(formattedNumber, smsText, smsUsr, smsPwd);
          return result;
       } catch(Exception e) {
            logger.error("Fail to send SMS " ,e );
            return false;
        }
    }
    
    public static String getMessage(RequiredActionContext context, String key){
        String result=null;
        try {
            ThemeProvider themeProvider = context.getSession().getProvider(ThemeProvider.class, "extending");
            Theme currentTheme = themeProvider.getTheme(context.getRealm().getLoginTheme(), Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
            result = currentTheme.getMessages(locale).getProperty(key);
        }catch (IOException e){
            logger.warn(key + "not found in messages");
        }
        return result;
    }

    
 // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private static void storeSMSCode(RequiredActionContext context, String code, Long expiringAt, String credType) {

		UserCredentialManager mgr = context.getSession().userCredentialManager();
    	
		List<CredentialModel> codeCreds = mgr.getStoredCredentialsByType(
				context.getRealm(), context.getUser(), credType);
        
		CredentialModel codeCredentials;
    
		if (codeCreds.isEmpty()) {
			codeCredentials = new CredentialModel();
			codeCredentials.setType(credType);
			codeCredentials.setCredentialData(code);
			codeCredentials.setSecretData(expiringAt.toString());
			mgr.createCredential(context.getRealm(), context.getUser(), codeCredentials);

		} else {
			codeCredentials = codeCreds.get(0);
			codeCredentials.setType(credType);
			codeCredentials.setCredentialData(code);
			codeCredentials.setSecretData(expiringAt.toString());
			mgr.updateCredential(context.getRealm(), context.getUser(), codeCredentials);
		}
    }

    public void processAction(RequiredActionContext context) {
        String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst("smsCode"));
        String answerForAltMobile = (context.getHttpRequest().getDecodedFormParameters().getFirst("altSmsCode"));
        List<FormMessage> errors = new ArrayList<>();
    	boolean isAltMobileNumberVerified = isAltMobileNumberVerified(context.getUser());
    	boolean isMobileNumberVerified = isMobileNumberVerified(context.getUser());
    	CODE_STATUS status = CODE_STATUS.INVALID;
    	
        if (!isMobileNumberVerified && Validation.isBlank(answer)){
        	errors.add(new FormMessage("smsCode", "MissingSMSCode"));
        }
        if (!isAltMobileNumberVerified && Validation.isBlank(answerForAltMobile)) {
        	errors.add(new FormMessage("altSmsCode", "MissingSMSCodeForAltMobile"));
        } 
        
        if(errors.isEmpty()) {
        	if(!isMobileNumberVerified) {
	        	status = validateCode(context, answer, USR_CRED_MDL_SMS_CODE);
	        	if(status == CODE_STATUS.EXPIRED || status == CODE_STATUS.INVALID) {
	        		errors.add(new FormMessage("smsCode", "MissingOrExpiredSMSCode"));
	        	}
        	}
        	if(!isAltMobileNumberVerified) {
        		status = validateCode(context, answerForAltMobile, USR_CRED_MDL_SMS_CODE_ALT);
        		if(status == CODE_STATUS.EXPIRED || status == CODE_STATUS.INVALID) {
            		errors.add(new FormMessage("altSmsCode", "MissingOrExpiredSMSCode"));
            	}
        	}
        }
        
        if (errors.size() > 0) {
        	context.form().setErrors(errors);
            context.failure();
        } else {
        	UserModel user = context.getUser();
            user.setSingleAttribute(ATTR_ALT_MOBILE_VERIFIED, getAltMobileNumber(user));
            user.setSingleAttribute(ATTR_MOBILE_VERIFIED, getMobileNumber(user));
            context.success();
        }
    }
    
    private CODE_STATUS validateCode(RequiredActionContext context, String enteredCode, String credType) {
    	UserCredentialManager mgr = context.getSession().userCredentialManager();
    	List<CredentialModel> codeCreds = mgr.getStoredCredentialsByType(
				context.getRealm(), context.getUser(), credType);
        CODE_STATUS result = CODE_STATUS.INVALID;

        if (!codeCreds.isEmpty()) {
        	CredentialModel codeCred = codeCreds.get(0);
        	long code_expiry_time = Long.parseLong(codeCred.getSecretData());
        	long now = new Date().getTime();
           
        	logger.debug("Expected code = " + codeCred.getCredentialData() + "    entered code = " + enteredCode);
        	logger.debug("Valid code expires in " + (code_expiry_time - now) + " ms");
        	
            result = enteredCode.equals(codeCred.getCredentialData()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
      
            if (result == CODE_STATUS.VALID && code_expiry_time < now) {
                    logger.debug("Code is expired !!");
                    result = CODE_STATUS.EXPIRED;
            }
        }
        logger.debug("mobile validation result : " + result);
        return result;
    }

    public void close() {
        logger.debug("close called ...");
    }
}
