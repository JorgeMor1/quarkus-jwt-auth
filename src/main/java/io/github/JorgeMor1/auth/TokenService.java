package io.github.JorgeMor1.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.JorgeMor1.usuarios.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.Claims;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class TokenService {
    @ConfigProperty(name = "mp.jwt.verify.issuer")
    String issue;
    @ConfigProperty(name = "mp.jwt.verify.audiences", defaultValue = "payment-api")
    String audience;
    private static final Duration ACCESS_TOKEN_DURATION = Duration.ofMinutes(15);

    @Inject
    KeyRotationManager keyRotationManager;

    public TokenResult  generateAccessToken( User user ) {
        if ( user.getRole() == null ) {
            throw new IllegalStateException( "Não é possível gerar um token para um usuário sem papel." );
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plus( ACCESS_TOKEN_DURATION );

        Set< String > roles = new HashSet<>();
        roles.add( user.getRole().getName() );

        try {
            RSAKey activeKey = keyRotationManager.getActiveSigningKey();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer( issue )
                    .audience(audience )
                    .subject( user.getEmail() )
                    .claim( "groups", roles )
                    .claim( "userId", user.getId().toString() )
                    .claim( Claims.jti.name(), UUID.randomUUID().toString() )
                    .issueTime( Date.from( now ) )
                    .expirationTime( Date.from(expiresAt ) )
                    .build();

            JWSHeader header = new JWSHeader.Builder( JWSAlgorithm.RS256 )
                    .keyID( activeKey.getKeyID() )
                    .type( com.nimbusds.jose.JOSEObjectType.JWT )
                    .build();

            SignedJWT signedJWT = new SignedJWT( header, claimsSet );
            JWSSigner signer = new RSASSASigner( activeKey.toRSAPrivateKey() );
            signedJWT.sign( signer );

            String accessToken = signedJWT.serialize();


            return new TokenResult( accessToken, expiresAt );
        } catch ( Exception e ) {
            throw new RuntimeException( "Erro crítico ao gerar token JWT assinado dinamicamente", e );
        }
    }
}
