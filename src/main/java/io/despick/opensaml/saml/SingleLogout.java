package io.despick.opensaml.saml;

import io.despick.opensaml.init.IDPMetadata;
import io.despick.opensaml.session.UserSession;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;

public class SingleLogout {

    public static LogoutResponse buildLogoutResponse(String requestID) {
        return buildLogoutResponse(requestID, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public static LogoutResponse buildLogoutResponse(String requestID, String requestBinding) {
        LogoutResponse logoutResponse = SAMLUtil.buildSAMLObject(LogoutResponse.class);
        logoutResponse.setID(SAMLUtil.getRandomID());
        logoutResponse.setInResponseTo(requestID);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setDestination(IDPMetadata.getIDPSLOServiceEndpointByBinding(requestBinding).getResponseLocation());
        logoutResponse.setIssuer(SAMLUtil.buildSPIssuer());
        logoutResponse.setStatus(buildSuccessStatus());

        return logoutResponse;
    }

    public static LogoutRequest buildLogoutRequest(UserSession userSession) {
        return buildLogoutRequest(userSession, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public static LogoutRequest buildLogoutRequest(UserSession userSession, String requestBinding) {
        LogoutRequest logoutRequest = SAMLUtil.buildSAMLObject(LogoutRequest.class);
        logoutRequest.setID(SAMLUtil.getRandomID());
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setDestination(IDPMetadata.getIDPSLOServiceEndpointByBinding(requestBinding).getLocation());
        logoutRequest.setIssuer(SAMLUtil.buildSPIssuer());
        // if the SAML name id and the session index were provided at login time, use them
        if (userSession != null) {
            if (userSession.getSamlNameID() != null) {
                logoutRequest.setNameID(userSession.getSamlNameID());
            }
            if (userSession.getSamlSessionIndex() != null) {
                logoutRequest.getSessionIndexes().add(buildSessionIndex(userSession));
            }
        }

        return logoutRequest;
    }

    private static SessionIndex buildSessionIndex(UserSession userSession) {
        SessionIndex sessionIndex = SAMLUtil.buildSAMLObject(SessionIndex.class);
        sessionIndex.setSessionIndex(userSession.getSamlSessionIndex());

        return sessionIndex;
    }

    private static Status buildSuccessStatus() {
        StatusCode statusCode = SAMLUtil.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);

        Status status = SAMLUtil.buildSAMLObject(Status.class);
        status.setStatusCode(statusCode);

        return status;
    }

}
