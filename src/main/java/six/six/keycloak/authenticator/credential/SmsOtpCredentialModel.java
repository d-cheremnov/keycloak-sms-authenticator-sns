package six.six.keycloak.authenticator.credential;

import java.io.IOException;

import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import six.six.keycloak.authenticator.credential.dto.SmsOtpCredentialData;
import six.six.keycloak.authenticator.credential.dto.SmsOtpSecretData;

public class SmsOtpCredentialModel extends CredentialModel {
	public final static String TYPE = "SMS-OTP";
	private SmsOtpCredentialData credentialData;
	private SmsOtpSecretData secretData;
	
	
	public SmsOtpCredentialModel(String secretOtp, String credentialOtp, String expiryTime) {
		credentialData = new SmsOtpCredentialData(credentialOtp);
		secretData = new SmsOtpSecretData(secretOtp, expiryTime);
	}
	private SmsOtpCredentialModel(SmsOtpCredentialData credentialData, SmsOtpSecretData secretData) {
		this.credentialData = credentialData;
		this.secretData = secretData;
	}

	public static SmsOtpCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
        	SmsOtpCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), SmsOtpCredentialData.class);
        	SmsOtpSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), SmsOtpSecretData.class);

        	SmsOtpCredentialModel otpCredentialModel = new SmsOtpCredentialModel(credentialData, secretData);
            otpCredentialModel.setUserLabel(credentialModel.getUserLabel());
            otpCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            otpCredentialModel.setType(TYPE);
            otpCredentialModel.setId(credentialModel.getId());
            otpCredentialModel.setSecretData(credentialModel.getSecretData());
            otpCredentialModel.setCredentialData(credentialModel.getCredentialData());
            return otpCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
	

}
