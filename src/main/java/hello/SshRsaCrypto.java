package hello;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.stream.Collectors;

import static java.security.KeyFactory.getInstance;

/**
 * Helper methods for using OpenSSH RSA private ({@code ~/.ssh/id_rsa})
 * and public ({@code ~/.ssh/id_rsa.pub}) keys to perform encryption
 * and decryption of Strings within the J2SE crypto framework.
 */

/**
 * Fork of https://github.com/fommil/openssh-java
 */
@Component
public class SshRsaCrypto {
	private static final Logger LOGGER = LoggerFactory.getLogger(SshRsaCrypto.class);

	public static final String RSA = "RSA";

	// http://msdn.microsoft.com/en-us/library/windows/desktop/bb540806%28v=vs.85%29.aspx
	private BigInteger readAsnInteger(DataInputStream in) throws IOException {
		checkArgument(in.read() == 2, "no INTEGER marker");
		int length = in.read();
		if (length >= 0x80) {
			byte[] extended = new byte[4];
			int bytesToRead = length & 0x7f;
			in.readFully(extended, 4 - bytesToRead, bytesToRead);
			length = new BigInteger(extended).intValue();
		}
		byte[] data = new byte[length];
		in.readFully(data);
		return new BigInteger(data);
	}

	private void checkArgument(boolean expression, String errorMessage) {
		if (!expression) {
			throw new IllegalArgumentException(String.valueOf(errorMessage));
		}
	}

	public PrivateKey readPrivateKey(byte[] bytes) throws GeneralSecurityException, IOException {
	/*
	 Key in the following ASN.1 DER encoding,
     RSAPrivateKey ::= SEQUENCE {
       version           Version,
       modulus           INTEGER,  -- n
       publicExponent    INTEGER,  -- e
       privateExponent   INTEGER,  -- d
       prime1            INTEGER,  -- p
       prime2            INTEGER,  -- q
       exponent1         INTEGER,  -- d mod (p-1)
       exponent2         INTEGER,  -- d mod (q-1)
       coefficient       INTEGER,  -- (inverse of q) mod p
       otherPrimeInfos   OtherPrimeInfos OPTIONAL
     }
   */
//		@Cleanup
		try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
			try {
				checkArgument(in.read() == 48, "no id_rsa SEQUENCE");
				checkArgument(in.read() == 130, "no Version marker");
				in.skipBytes(5);

				BigInteger n = readAsnInteger(in);
				readAsnInteger(in);
				BigInteger e = readAsnInteger(in);

				RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, e);
				return getInstance(RSA).generatePrivate(spec);
			} catch (NoSuchAlgorithmException ex) {
				throw new IllegalStateException(ex);
			}
		}
	}

	public PublicKey readPublicKey(byte[] bytes) throws GeneralSecurityException, IOException {
		// http://stackoverflow.com/questions/12749858
		// http://tools.ietf.org/html/rfc4716
		// http://tools.ietf.org/html/rfc4251
//		@Cleanup
		try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
			try {
				byte[] sshRsa = new byte[in.readInt()];
				in.readFully(sshRsa);
				checkArgument(new String(sshRsa).equals("ssh-rsa"), "no RFC-4716 ssh-rsa");
				byte[] exp = new byte[in.readInt()];
				in.readFully(exp);
				byte[] mod = new byte[in.readInt()];
				in.readFully(mod);

				BigInteger e = new BigInteger(exp);
				BigInteger n = new BigInteger(mod);
				RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
				return getInstance(RSA).generatePublic(spec);
			} catch (NoSuchAlgorithmException ex) {
				throw new IllegalStateException(ex);
			}
		}
	}

	/**
	 * @param body of {@code ~/.ssh/id_rsa}
	 * @return binary form suitable for use in {@link #readPrivateKey(byte[])}
	 * @throws IOException
	 */
	public byte[] slurpPrivateKey(String body) throws IOException {
		String ascii = IOUtils
				.readLines(new StringReader(body))
				.stream()
				.filter(line -> !(line.contains("-") || line.contains(":")))
				.collect(Collectors.joining(""));
		Base64 b64 = new Base64();
		return b64.decode(ascii);
	}

	/**
	 * @param body of a single entry {@code ~/.ssh/id_rsa.pub}
	 * @return binary form suitable for use in {@link #readPublicKey(byte[])}
	 */
	public byte[] slurpPublicKey(String body) {
		String[] contents = body.split(" ");

		if (contents.length == 0) {
			throw new IllegalArgumentException("Provided public key is empty");
		}

		Base64 b64 = new Base64();
		byte[] result = null;
		if (contents.length == 1) {
			String content = contents[0];
			LOGGER.debug("Provided public key contains only key part and no headers. Decoding base64 from {}", content);
			result = b64.decode(content);
		}

		if (contents.length == 3) {
			String content = contents[1];
			LOGGER.debug("Full public key. Decoding base64 from {}", content);
			result = b64.decode(content);
		}

		return result;
	}
}
