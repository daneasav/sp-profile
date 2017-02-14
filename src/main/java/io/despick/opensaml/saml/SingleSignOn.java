package io.despick.opensaml.saml;

import io.despick.opensaml.init.IDPMetadata;
import io.despick.opensaml.init.SPMetadata;
import org.joda.time.DateTime;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;

public class SingleSignOn {

    public static AuthnRequest buildAuthnRequest() {
        return buildAuthnRequest(AuthnContext.PPT_AUTHN_CTX);
    }

    public static AuthnRequest buildAuthnRequest(String authnContext) {
        return buildAuthnRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_ARTIFACT_BINDING_URI, authnContext, AuthnContextComparisonTypeEnumeration.EXACT);
    }

    private static AuthnRequest buildAuthnRequest(String requestBinding, String responseBinding, String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
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

    private static NameIDPolicy buildTransientNameIdPolicy() {
        NameIDPolicy nameIDPolicy = SAMLUtil.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private static RequestedAuthnContext buildRequestedAuthnContext(String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
        AuthnContextClassRef passwordAuthnContextClassRef = SAMLUtil.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(authnContext);

        RequestedAuthnContext requestedAuthnContext = SAMLUtil.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(criteria);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;
    }

    public static Artifact buildArtifact(String artifactID) {
        Artifact artifact = SAMLUtil.buildSAMLObject(Artifact.class);
        artifact.setArtifact(artifactID);
        return artifact;
    }

    public static ArtifactResolve buildArtifactResolve(Artifact artifact) {
        ArtifactResolve artifactResolve = SAMLUtil.buildSAMLObject(ArtifactResolve.class);
        artifactResolve.setIssuer(SAMLUtil.buildSPIssuer());
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(SAMLUtil.getRandomID());
        artifactResolve.setDestination(IDPMetadata.getArtifactResolutionService());
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

}
