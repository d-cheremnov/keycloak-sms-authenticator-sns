package six.six.keycloak;

import java.util.List;

import org.keycloak.models.UserModel;

public class MobileNumberHelper {
    public static String getMobileNumber(UserModel user) {
        String mobileNumberCreds = user.getFirstAttribute(KeycloakSmsConstants.ATTR_MOBILE);

        String mobileNumber = null;

        if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
            mobileNumber = mobileNumberCreds;
        }

        return mobileNumber;
    }
    
    public static String getAltMobileNumber(UserModel user) {
        String altMobileNumberCreds = user.getFirstAttribute(KeycloakSmsConstants.ATTR_ALT_MOBILE);

        String mobileNumber = null;

        if (altMobileNumberCreds != null && !altMobileNumberCreds.isEmpty()) {
            mobileNumber = altMobileNumberCreds;
        }

        return mobileNumber;
    }
    
    public static String getMobileNumberVerified(UserModel user){
        List<String> mobileNumberVerifieds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED);

        String mobileNumberVerified = null;
        if (mobileNumberVerifieds != null && !mobileNumberVerifieds.isEmpty()) {
            mobileNumberVerified = mobileNumberVerifieds.get(0);
        }
        return  mobileNumberVerified;
    }
    
    public static String getAltMobileNumberVerified(UserModel user){
        List<String> mobileNumberVerifieds = user.getAttribute(KeycloakSmsConstants.ATTR_ALT_MOBILE_VERIFIED);

        String mobileNumberVerified = null;
        if (mobileNumberVerifieds != null && !mobileNumberVerifieds.isEmpty()) {
            mobileNumberVerified = mobileNumberVerifieds.get(0);
        }
        return  mobileNumberVerified;
    }
    
    public static boolean isMobileNumberVerified(UserModel user) {    	
    	return  getMobileNumber(user).equals(getMobileNumberVerified(user)) ;
    	
    }
    
    public static boolean isAltMobileNumberVerified(UserModel user) {    	
    	return getAltMobileNumber(user)==null || 
    			getAltMobileNumber(user).equals(getAltMobileNumberVerified(user)) ;
    	
    }
    
}
