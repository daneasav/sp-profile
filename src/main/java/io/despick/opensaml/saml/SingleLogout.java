package io.despick.opensaml.saml;

import io.despick.opensaml.init.IDPMetadata;
import io.despick.opensaml.saml.session.UserSession;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;

public class SingleLogout {

    public LogoutResponse buildLogoutResponse(String requestID) {
        return buildLogoutResponse(requestID, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public LogoutResponse buildLogoutResponse(String requestID, String requestBinding) {
        LogoutResponse logoutResponse = SAMLUtil.buildSAMLObject(LogoutResponse.class);
        logoutResponse.setID(SAMLUtil.getRandomID());
        logoutResponse.setInResponseTo(requestID);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setDestination(IDPMetadata.getIDPSLOServiceEndpointByBinding(requestBinding).getResponseLocation());
        logoutResponse.setIssuer(SAMLUtil.buildSPIssuer());
        logoutResponse.setStatus(buildSuccessStatus());

        return logoutResponse;
    }

    public LogoutRequest buildLogoutRequest(UserSession userSession) {
        return buildLogoutRequest(userSession, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public LogoutRequest buildLogoutRequest(UserSession userSession, String requestBinding) {
        LogoutRequest logoutRequest = SAMLUtil.buildSAMLObject(LogoutRequest.class);
        logoutRequest.setID(SAMLUtil.getRandomID());
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setDestination(IDPMetadata.getIDPSLOServiceEndpointByBinding(requestBinding).getLocation());
        logoutRequest.setIssuer(SAMLUtil.buildSPIssuer());
        logoutRequest.setNameID(buildNameID(userSession));
        logoutRequest.getSessionIndexes().add(buildSessionIndex(userSession));

        return logoutRequest;
    }

    private SessionIndex buildSessionIndex(UserSession userSession) {
        SessionIndex sessionIndex = SAMLUtil.buildSAMLObject(SessionIndex.class);
        sessionIndex.setSessionIndex(userSession.getSamlSessionIndex());

        return sessionIndex;
    }

    private NameID buildNameID(UserSession userSession) {
        return userSession.getSamlNameID();
    }

    private Status buildSuccessStatus() {
        StatusCode statusCode = SAMLUtil.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);

        Status status = SAMLUtil.buildSAMLObject(Status.class);
        status.setStatusCode(statusCode);

        return status;
    }

}
