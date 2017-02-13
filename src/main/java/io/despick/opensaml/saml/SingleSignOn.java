package io.despick.opensaml.saml;

import io.despick.opensaml.init.SamlMetadata;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.*;

import javax.xml.namespace.QName;
import java.util.List;

/**
 * Created by DaneasaV on 09.02.2017.
 */
public class SingleSignOn {

    public AuthnRequest buildAuthnRequest() {
        return buildAuthnRequest(AuthnContext.PPT_AUTHN_CTX);
    }

    public AuthnRequest buildAuthnRequest(String authnContext) {
        return buildAuthnRequest(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_ARTIFACT_BINDING_URI, authnContext, AuthnContextComparisonTypeEnumeration.EXACT);
    }

    //SAMLConstants.SAML2_ARTIFACT_BINDING_URI
    private AuthnRequest buildAuthnRequest(String requestBinding, String responseBinding, String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(getIDPDestinationByBinding(
            SamlMetadata.idpDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS), requestBinding));
        authnRequest.setProtocolBinding(responseBinding);
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint(
            SamlMetadata.spDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS), responseBinding));
        authnRequest.setID(SamlMetadata.secureRandomIdGenerator.generateIdentifier());
        authnRequest.setIssuer(buildSPIssuer(SamlMetadata.spDescriptor));
        authnRequest.setNameIDPolicy(buildTransientNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext(authnContext, criteria));

        return authnRequest;
    }

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    private String getIDPDestinationByBinding(IDPSSODescriptor idpssoDescriptor, String binding) {
        List<SingleSignOnService> singleSignOnServices = idpssoDescriptor.getSingleSignOnServices();

        for (SingleSignOnService ssoService : singleSignOnServices) {
            if (ssoService.getBinding().equals(binding)) {
                return ssoService.getLocation();
            }
        }

        // TODO: return fallback binding
        return null;
    }

    private String getAssertionConsumerEndpoint(SPSSODescriptor spssoDescriptor, String binding) {
        List<AssertionConsumerService> assertionConsumerServices = spssoDescriptor.getAssertionConsumerServices();

        for (AssertionConsumerService assertionConsumerService : assertionConsumerServices) {
            if (assertionConsumerService.getBinding().equals(binding)) {
                return assertionConsumerService.getLocation();
            }
        }

        // TODO: return fallback binding
        return null;
    }

    private Issuer buildSPIssuer(EntityDescriptor entityDescriptor) {
        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(entityDescriptor.getEntityID());

        return issuer;
    }

    private NameIDPolicy buildTransientNameIdPolicy() {
        NameIDPolicy nameIDPolicy = buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private RequestedAuthnContext buildRequestedAuthnContext(String authnContext, AuthnContextComparisonTypeEnumeration criteria) {
        AuthnContextClassRef passwordAuthnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(authnContext);

        RequestedAuthnContext requestedAuthnContext = buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(criteria);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;
    }


}
