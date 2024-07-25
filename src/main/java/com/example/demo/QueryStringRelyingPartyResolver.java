package com.example.demo;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.stereotype.Component;

@Component
public class QueryStringRelyingPartyResolver implements RelyingPartyRegistrationResolver {

    private final RelyingPartyRegistrationResolver delegate;

    public QueryStringRelyingPartyResolver(RelyingPartyRegistrationRepository registrations) {
        this.delegate = new DefaultRelyingPartyRegistrationResolver(registrations);
    }

    @Override
    public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
       // relyingPartyRegistrationId = relyingPartyRegistrationId == null ? request.getParameter("idp") : "okta";
        String relyingPartyRegistrationId1 = request.getRequestURI().split("/")[4];

        return this.delegate.resolve(request, relyingPartyRegistrationId1);
    }
}