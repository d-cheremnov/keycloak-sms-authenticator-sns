package six.six.keycloak.authenticator.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SmsOtpSecretData {
    private final String value;
    private final String expiryTime;

    @JsonCreator
    public SmsOtpSecretData(@JsonProperty("value") String value, @JsonProperty("expiryTime") String expiryTime) {
        this.value = value;
        this.expiryTime = expiryTime;
    }

    public String getValue() {
        return value;
    }
    
    public String getExpiryTime() {
    	return expiryTime;
    }
}