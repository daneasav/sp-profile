package io.despick.opensaml.saml;

import io.despick.opensaml.config.IDPMetadata;
import io.despick.opensaml.config.SAMLConfigProperties;
import io.despick.opensaml.config.SPMetadata;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.*;

import java.util.EnumSet;

public class SingleSignOn {

    public static AuthnRequest buildPassiveAuthnRequest() {
        return buildPassiveAuthnRequest(SAMLConfigProperties.getSSOAuthnContext());
    }

    public static AuthnRequest buildPassiveAuthnRequest(String authnContext) {

        return buildAuthnRequest(SAMLConfigProperties.getSSOBindingRequest(), SAMLConfigProperties.getSSOBindingResponse(),
            true, authnContext, AuthnContextComparisonTypeEnumeration.EXACT);
    }

    public static AuthnRequest buildAuthnRequest() {
        return buildAuthnRequest(SAMLConfigProperties.getSSOAuthnContext());
    }

    public static AuthnRequest buildAuthnRequest(String authnContext) {
        return buildAuthnRequest(SAMLConfigProperties.getSSOBindingRequest(), SAMLConfigProperties.getSSOBindingResponse(),
            false, authnContext, AuthnContextComparisonTypeEnumeration.EXACT);
    }

    public static AuthnRequest buildAuthnRequest(String requestBinding, String responseBinding, String authnContext) {
        return buildAuthnRequest(requestBinding, responseBinding, false, authnContext,
            AuthnContextComparisonTypeEnumeration.EXACT);
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

    private static AuthnRequest buildAuthnRequest(String requestBinding, String responseBinding, boolean isPassive,
        String authnContext, AuthnContextComparisonTypeEnumeration criteria) {

        AuthnRequest authnRequest = SAMLUtil.buildSAMLObject(AuthnRequest.class);
        authnRequest.setID(SAMLUtil.getRandomID());
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(IDPMetadata.getIDPSSOServiceEndpointByBinding(requestBinding).getLocation());
        authnRequest.setForceAuthn(false);
        authnRequest.setIsPassive(isPassive);
        authnRequest.setProtocolBinding(responseBinding);
        authnRequest.setIssuer(SAMLUtil.buildSPIssuer());
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

}
