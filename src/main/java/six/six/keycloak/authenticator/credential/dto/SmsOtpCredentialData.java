package six.six.keycloak.authenticator.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SmsOtpCredentialData {
    private final String value;

    @JsonCreator
    public SmsOtpCredentialData(@JsonProperty("value") String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}