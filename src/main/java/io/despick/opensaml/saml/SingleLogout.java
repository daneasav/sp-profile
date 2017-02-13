package io.despick.opensaml.saml;

import io.despick.opensaml.init.SamlMetadata;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;

import java.util.List;

/**
 * Created by DaneasaV on 13.02.2017.
 */
public class SingleLogout {

    public LogoutResponse buildLogoutResponse(String requestID) {
        return buildLogoutResponse(requestID, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public LogoutResponse buildLogoutResponse(String requestID, String requestBinding) {
        LogoutResponse logoutResponse = SAMLUtil.buildSAMLObject(LogoutResponse.class);
        logoutResponse.setID(SAMLUtil.secureRandomIdGenerator.generateIdentifier());
        logoutResponse.setInResponseTo(requestID);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setDestination(getIDPResponseDestinationByBinding(
                SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS),
                requestBinding));
        logoutResponse.setIssuer(buildSPIssuer(SamlMetadata.spDescriptor));
        logoutResponse.setStatus(buildSuccessStatus());

        return logoutResponse;
    }

    public LogoutRequest buildLogoutRequest(UserSession userSession) {
        return buildLogoutRequest(userSession, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }

    public LogoutRequest buildLogoutRequest(UserSession userSession, String requestBinding) {
        LogoutRequest logoutRequest = SAMLUtil.buildSAMLObject(LogoutRequest.class);
        logoutRequest.setID(SAMLUtil.secureRandomIdGenerator.generateIdentifier());
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setDestination(getIDPDestinationByBinding(
            SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS),
            requestBinding));
        logoutRequest.setIssuer(buildSPIssuer(SamlMetadata.spDescriptor));
        logoutRequest.setNameID(buildNameID(userSession));
        logoutRequest.getSessionIndexes().add(buildSessionIndex(userSession));

        return logoutRequest;
    }

    private Issuer buildSPIssuer(EntityDescriptor entityDescriptor) {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(entityDescriptor.getEntityID());

        return issuer;
    }

    private String getIDPDestinationByBinding(IDPSSODescriptor idpssoDescriptor, String requestBinding) {
        for (SingleLogoutService sloService : idpssoDescriptor.getSingleLogoutServices()) {
            if (sloService.getBinding().equals(requestBinding)) {
                return sloService.getLocation();
            }
        }

        return null;
    }

    private String getIDPResponseDestinationByBinding(IDPSSODescriptor idpssoDescriptor, String requestBinding) {
        for (SingleLogoutService sloService : idpssoDescriptor.getSingleLogoutServices()) {
            if (sloService.getBinding().equals(requestBinding)) {
                return sloService.getResponseLocation();
            }
        }

        return null;
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
