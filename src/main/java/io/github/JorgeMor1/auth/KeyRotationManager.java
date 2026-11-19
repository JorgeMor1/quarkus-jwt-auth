package io.github.JorgeMor1.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.JorgeMor1.auth.model.RsaKeyEntity;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.transaction.Transactional;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@ApplicationScoped
public class KeyRotationManager {

    @Transactional
    public void onStart(@Observes StartupEvent event) {
        long activeCount = RsaKeyEntity.count("status", "ACTIVE");
        if (activeCount == 0) {
            try {
                generateAndSaveNewKeyPair("key-" + UUID.randomUUID().toString().substring(0, 8));
            } catch (Exception e) {
                throw new RuntimeException("Falha crítica ao gerar par de chaves RSA inicial", e);
            }
        }
    }

    /**
     * Retorna a chave ativa atual
     */
    @Transactional
    public RSAKey getActiveSigningKey() throws Exception {
        RsaKeyEntity activeEntity = RsaKeyEntity.find("status", "ACTIVE").firstResult();

        if (activeEntity == null) {
            // Fallback blindado caso a chave ativa tenha sido removida manualmente em tempo de execução
            activeEntity = generateAndSaveNewKeyPair("key-" + UUID.randomUUID().toString().substring(0, 8));
        }

        return parseToNimbusRSAKey(activeEntity);
    }

    /**
     * Retorna o JWKS contendo estritamente chaves válidas (ACTIVE e DEPRECATED)
     * Chaves EXPIRED são ocultadas
     */
    public JWKSet getPublicJwkSet() throws Exception {
        List<RsaKeyEntity> validKeys = RsaKeyEntity.list("status != ?1", "EXPIRED");
        List<com.nimbusds.jose.jwk.JWK> jwks = new java.util.ArrayList<>();

        for (RsaKeyEntity entity : validKeys) {
            try {
                // Converte o PEM da chave pública para RSAPublicKey do Java
                RSAPublicKey pubKey = loadPublicKeyFromPem(entity.publicKey);

                // Constrói o JWK público limpo atrelando o kid
                RSAKey publicRsaKey = new RSAKey.Builder(pubKey)
                        .keyID(entity.kid)
                        .build();

                jwks.add(publicRsaKey);
            } catch (Exception e) {
                throw new RuntimeException("Erro ao parsear chave pública para o JWKS com o kid: " + entity.kid, e);
            }
        }

        return new JWKSet(jwks);
    }

    /**
     * Gera um novo par de chaves RSA de 2048 bits seguindo as diretrizes do NIST
     */
    @Transactional
    public RsaKeyEntity generateAndSaveNewKeyPair(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n-----END PRIVATE KEY-----";
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----";

        RsaKeyEntity entity = new RsaKeyEntity();
        entity.kid = kid;
        entity.privateKey = privateKeyPem; // Criptografada automaticamente pelo AttributeConverter
        entity.publicKey = publicKeyPem;
        entity.status = "ACTIVE";
        entity.createdAt = Instant.now();
        entity.expiresAt = Instant.now().plus(90, ChronoUnit.DAYS); // Ciclo de vida de 90 dias

        entity.persist();
        return entity;
    }

    private RSAKey parseToNimbusRSAKey(RsaKeyEntity entity) throws Exception {
        // Converte tanto o PEM público quanto o privado para os tipos do Java nativo
        RSAPublicKey pubKey = loadPublicKeyFromPem(entity.publicKey);
        RSAPrivateKey privKey = loadPrivateKeyFromPem(entity.privateKey);

        return new RSAKey.Builder(pubKey)
                .privateKey(privKey)
                .keyID(entity.kid)
                .build();
    }

    private RSAPrivateKey loadPrivateKeyFromPem(String pem) throws Exception {
        String cleaned = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    private RSAPublicKey loadPublicKeyFromPem(String pem) throws Exception {
        String cleaned = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }
}
