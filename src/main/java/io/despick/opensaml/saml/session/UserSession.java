package io.despick.opensaml.saml.session;

import org.opensaml.saml.saml2.core.NameID;

public class UserSession {

    // SAML specific attributes
    private String samlSessionIndex;
    private NameID samlNameID;

    // OpenAM specific attributes
    private String ssoToken;
    private int authLevel;

    // user attributes
    private String userID;
    private String hssiID;
    private String email;
    private String salutation;
    private String firstName;
    private String lastName;

    public String getSamlSessionIndex() {
        return samlSessionIndex;
    }

    public void setSamlSessionIndex(String samlSessionIndex) {
        this.samlSessionIndex = samlSessionIndex;
    }

    public NameID getSamlNameID() {
        return samlNameID;
    }

    public void setSamlNameID(NameID samlNameID) {
        this.samlNameID = samlNameID;
    }

    public String getSsoToken() {
        return ssoToken;
    }

    public void setSsoToken(String ssoToken) {
        this.ssoToken = ssoToken;
    }

    public int getAuthLevel() {
        return authLevel;
    }

    public void setAuthLevel(int authLevel) {
        this.authLevel = authLevel;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getHssiID() {
        return hssiID;
    }

    public void setHssiID(String hssiID) {
        this.hssiID = hssiID;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSalutation() {
        return salutation;
    }

    public void setSalutation(String salutation) {
        this.salutation = salutation;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
}
