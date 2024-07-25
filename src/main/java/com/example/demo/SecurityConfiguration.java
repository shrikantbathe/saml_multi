package com.example.demo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    /*oidc*/
    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/fgn").permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(Customizer.withDefaults())
                .saml2Logout(Customizer.withDefaults());
        return http.build();
    }

//    @Bean
//    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver( RelyingPartyRegistrationRepository registrations) {
//        return new DefaultRelyingPartyRegistrationResolver((id) -> registrations.findByRegistrationId("okta"));
//    }

    @Bean
    Saml2AuthenticationTokenConverter authentication(RelyingPartyRegistrationResolver registrations) {
        return new Saml2AuthenticationTokenConverter(registrations);
    }

    @Bean
    FilterRegistrationBean<Saml2MetadataFilter> metadata(RelyingPartyRegistrationResolver registrations) {
        Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
        FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
        filter.setOrder(-101);
        return filter;
    }

    @Bean
    RelyingPartyRegistrationRepository repository( @Value("classpath:rp-private.key") RSAPrivateKey privateKey) {

          Saml2X509Credential signing = Saml2X509Credential.signing(privateKey, relyingPartyCertificate());
        RelyingPartyRegistration two = RelyingPartyRegistrations
//                .fromMetadataLocation("https://dev-98822192.okta.com/app/exkia77455ZN7RYBS5d7/sso/saml/metadata")
//                .registrationId("okta")
                .fromMetadataLocation("https://dev-05937739.okta.com/app/exk4842vmapcMkohr5d7/sso/saml/metadata")
                .registrationId("two")
                    .signingX509Credentials((c) -> c.add(signing))
                .singleLogoutServiceLocation("http://localhost:8080/logout/saml2/slo")
                .build();


        //   Saml2X509Credential signing = Saml2X509Credential.signing(privateKey, relyingPartyCertificate());
        RelyingPartyRegistration okta = RelyingPartyRegistrations
                .fromMetadataLocation("https://dev-98822192.okta.com/app/exkia77455ZN7RYBS5d7/sso/saml/metadata")
                .registrationId("okta")
                //.signingX509Credentials((c) -> c.add(signing))
                .singleLogoutServiceLocation("http://localhost:8080/logout/saml2/slo")
                .build();


        return new InMemoryRelyingPartyRegistrationRepository(okta,two);
    }

    X509Certificate relyingPartyCertificate() {
        Resource resource = new ClassPathResource("rp-certificate.crt");
        try (InputStream is = resource.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
        catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }
}