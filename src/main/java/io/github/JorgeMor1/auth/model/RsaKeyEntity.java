package io.github.JorgeMor1.auth.model;

import io.github.JorgeMor1.auth.EncryptedStringConverter;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(
        name = "rsa_keys",
        indexes = {
                @Index(name = "idx_rsa_keys_status", columnList = "status")
        }
)
public class RsaKeyEntity extends PanacheEntityBase {

        @Id
        @Column(name = "id", length = 50)
        public String kid;

        @Convert(converter = EncryptedStringConverter.class)
        @Column(name = "private_key", nullable = false, columnDefinition = "TEXT")
        public String privateKey;

        @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
        public String publicKey;

        @Column(name = "status", nullable = false, length = 20)
        public String status; // 'ACTIVE', 'DEPRECATED', 'EXPIRED'

        @Column(name = "created_at", nullable = false, updatable = false)
        public Instant createdAt;

        @Column(name = "expires_at", nullable = false)
        public Instant expiresAt;

        @PrePersist
        public void prePersist() {
            if (this.createdAt == null) {
                this.createdAt = Instant.now();
            }
        }

}
