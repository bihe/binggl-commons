package net.binggl.commons.crypto;

import static org.junit.Assert.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import net.binggl.commons.crypto.AesEncryption;

public class EncryptionTest {

	@Test
	public void testEncryption() {
		AesEncryption aesCrypto = new AesEncryption();
		
		String key = "this_is_my_secret_password";
		String plain = "You can read me";

		// 1. Roundtrip
		String encrypted = aesCrypto.encrypt(key, plain);
		assertNotNull(encrypted);
		assertTrue(StringUtils.isNotEmpty(encrypted));
		String decrypted = aesCrypto.decryptAsString(key, encrypted);
		assertNotNull(decrypted);
		assertEquals(plain, decrypted);
		
		// 2. Decrypt with other instance - same result
		AesEncryption aesCrypto1 = new AesEncryption();
		decrypted = aesCrypto1.decryptAsString(key, encrypted);
		assertNotNull(decrypted);
		assertEquals(plain, decrypted);
		
		// 3. encryption-result is different with a new instance
		String encrypted1 = aesCrypto1.encrypt(key, plain);
		assertNotNull(encrypted1);
		assertTrue(StringUtils.isNotEmpty(encrypted1));
		assertNotEquals(encrypted, encrypted1);
	}
}