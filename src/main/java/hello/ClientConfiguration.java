package hello;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

@Configuration
public class ClientConfiguration {
    @Value("${jwt.public-key}")
    private String publicRsaKey;

    @Bean
    public PublicKey publicKey(SshRsaCrypto sshRsaCrypto) {
        try {
            return sshRsaCrypto.readPublicKey(sshRsaCrypto.slurpPublicKey(publicRsaKey));
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
