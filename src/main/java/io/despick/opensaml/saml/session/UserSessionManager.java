package io.despick.opensaml.saml.session;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

public class UserSessionManager {

    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "user.session.attribute";

    public static UserSession getUserSession(HttpServletRequest request) {
        return (UserSession) request.getSession().getAttribute(AUTHENTICATED_SESSION_ATTRIBUTE);
    }

    public static void setUserSession(HttpServletRequest request, UserSession userSession) {
        request.getSession().setAttribute(AUTHENTICATED_SESSION_ATTRIBUTE, userSession);
    }

    public static void removeUserSession(HttpServletRequest request) {
        request.getSession().removeAttribute(AUTHENTICATED_SESSION_ATTRIBUTE);
    }

    public static boolean isUserSession(HttpServletRequest request) {
        return getUserSession(request) != null;
    }

    public static UserSession getUserSession(Assertion assertion) {
        UserSession userSession = new UserSession();

        // remove nameid from the dom; it is used by SLO processes
        assertion.getSubject().getNameID().detach();
        userSession.setSamlNameID(assertion.getSubject().getNameID());

        // TODO only one authn statement is expected
        //set the session index; it is used by SLO processes
        if (assertion.getAuthnStatements().size() == 1) {
            userSession.setSamlSessionIndex(assertion.getAuthnStatements().get(0).getSessionIndex());
        }

        // set attributes
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                List<XMLObject> attributeValues = attribute.getAttributeValues();

                if (!attributeValues.isEmpty()) {
                    switch (attribute.getName()) {
                        case "SSOToken":
                            userSession.setSsoToken(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "AuthLevel":
                            userSession.setAuthLevel(Integer.parseInt(getAttributeValue(attributeValues.get(0))));
                            break;
                        case "HMGUSERID":
                            userSession.setUserID(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "huid":
                            userSession.setHssiID(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "Salutation":
                            userSession.setSalutation(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "FirstName":
                            userSession.setFirstName(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "LastName":
                            userSession.setLastName(getAttributeValue(attributeValues.get(0)));
                            break;
                        case "Email":
                            userSession.setEmail(getAttributeValue(attributeValues.get(0)));
                            break;
                    }
                }
            }
        }

        return userSession;
    }

    private static String getAttributeValue(XMLObject attributeValue) {
        return attributeValue == null ? null :
            attributeValue instanceof XSString ? getStringAttributeValue((XSString) attributeValue) :
                attributeValue instanceof XSAnyImpl ? getAnyAttributeValue((XSAnyImpl) attributeValue) :
                    attributeValue.toString();
    }

    private static String getStringAttributeValue(XSString attributeValue) {
        return attributeValue.getValue();
    }

    private static String getAnyAttributeValue(XSAnyImpl attributeValue) {
        return attributeValue.getTextContent();
    }

}
