package com.mudra.bootsecurity;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
public class BootSecurityConfig {

    // @Autowired
    // RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    Saml2RelyingPartyProperties relyingPartyProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        Saml2MetadataFilter filter = new Saml2MetadataFilter(new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrations()),
                new OpenSamlMetadataResolver());

        Converter<Assertion, Collection<? extends GrantedAuthority>> authoritiesExtractor = assertion -> {

        List<SimpleGrantedAuthority> userRoles =   assertion.getAttributeStatements().stream()
                    .map(AttributeStatement::getAttributes)
                    .flatMap(Collection::stream)
                    .filter(attr -> "groups".equalsIgnoreCase(attr.getName()))
                    .map(Attribute::getAttributeValues)
                    .flatMap(Collection::stream)
                    .map(xml -> new SimpleGrantedAuthority("ROLE_" + xml.getDOM().getTextContent()))
                    .toList();
        return userRoles;
        };

        Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> authConverter = OpenSaml4AuthenticationProvider
                                                                                                        .createDefaultResponseAuthenticationConverter();
        OpenSaml4AuthenticationProvider samlAuthProvider = new OpenSaml4AuthenticationProvider();
        samlAuthProvider.setResponseAuthenticationConverter((responseToken) -> {

            Saml2Authentication authentication = authConverter.convert(responseToken);
            Assertion assertion = responseToken.getResponse().getAssertions().get(0);
            AuthenticatedPrincipal principal = (AuthenticatedPrincipal) authentication.getPrincipal();
            Collection<? extends  GrantedAuthority> authorities = authoritiesExtractor.convert(assertion);/*
            System.out.println(principal.getName());
            authorities.stream().forEach(c -> System.out.println(c));*/
            return  new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        });


        /*
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(responseToken -> {
            Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter()
                    .convert(responseToken);
            Assertion assertion = responseToken.getResponse().getAssertions().get(0);
            String username = assertion.getSubject().getNameID().getValue();
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            return MySaml2Authentication(userDetails, authentication);
        });
         */

        httpSecurity.saml2Login(Customizer.withDefaults())
                .saml2Logout(Customizer.withDefaults())
                .authenticationProvider(samlAuthProvider)
                .addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class)
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/","/carsonline","/buyCar").hasAnyRole("cars.user","cars.admin")
                        .requestMatchers("/editCar").hasAnyRole("cars.admin")
                        .anyRequest().authenticated());

        return httpSecurity.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        String registrationId = this.relyingPartyProperties.getRegistration().keySet().stream().findFirst().get();

        Saml2RelyingPartyProperties.Registration registration = this.relyingPartyProperties.getRegistration().get("carsonline");
        System.out.println(registration.getEntityId());

        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(registration.getAssertingparty().getMetadataUri())
                .signingX509Credentials((credentials) -> registration.getSigning().getCredentials().stream()
                        .map(this::asSigningCredential).forEach(credentials::add))
                .decryptionX509Credentials((credentials) -> registration.getSigning().getCredentials().stream()
                        .map(this::asDecryptCredential).forEach(credentials::add))
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .registrationId(registrationId).build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);

    }

    private Saml2X509Credential asSigningCredential(
            Saml2RelyingPartyProperties.Registration.Signing.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }

    private Saml2X509Credential asDecryptCredential(
            Saml2RelyingPartyProperties.Registration.Signing.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
    }

    private RSAPrivateKey readPrivateKey(Resource location) {
        try (InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        }
        catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private X509Certificate readCertificate(Resource location) {
        try (InputStream inputStream = location.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        }
        catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }
}
