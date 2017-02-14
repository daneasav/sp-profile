package io.despick.opensaml.saml;

import io.despick.opensaml.init.IDPMetadata;
import io.despick.opensaml.init.SPMetadata;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;

public class SingleSignOn {

    public AuthnRequest buildAuthnRequest() {
        return buildAuthnRequest(AuthnContext.PPT_AUTHN_CTX);
    }

    public AuthnRequest buildAuthnRequest(String authnContext) {
        return buildAuthnRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_ARTIFACT_BINDING_URI, authnContext, AuthnContextComparisonTypeEnumeration.EXACT);
    }

    private AuthnRequest buildAuthnRequest(String requestBinding, String responseBinding, String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
        AuthnRequest authnRequest = SAMLUtil.buildSAMLObject(AuthnRequest.class);
        authnRequest.setID(SAMLUtil.getRandomID());
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(IDPMetadata.getIDPSSOServiceEndpointByBinding(requestBinding).getLocation());
        authnRequest.setIssuer(SAMLUtil.buildSPIssuer());
        authnRequest.setProtocolBinding(responseBinding);
        authnRequest.setAssertionConsumerServiceURL(SPMetadata.getAssertionConsumerEndpoint(responseBinding));
        authnRequest.setNameIDPolicy(buildTransientNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(authnContext, criteria));

        return authnRequest;
    }

    private NameIDPolicy buildTransientNameIdPolicy() {
        NameIDPolicy nameIDPolicy = SAMLUtil.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private RequestedAuthnContext buildRequestedAuthnContext(String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
        AuthnContextClassRef passwordAuthnContextClassRef = SAMLUtil.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(authnContext);

        RequestedAuthnContext requestedAuthnContext = SAMLUtil.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(criteria);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;
    }


}
