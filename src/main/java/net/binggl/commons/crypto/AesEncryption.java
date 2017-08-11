package net.binggl.commons.crypto;

import static net.binggl.commons.util.ExceptionHelper.wrapEx;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AesEncryption {
	
	private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5PADDING"; 
	private static final String ALGORITHM_AES = "AES";
	private static final String ALGORITHM_SHA = "SHA-256";
	private static final int KEY_SIZE = 16; // 128
	private static final Logger logger = LoggerFactory.getLogger(AesEncryption.class);
	private static final int IV_VECTOR_LENGTH = 16;

	public AesEncryption() {
	}

    /**
     * encrypt a string
     * @param key the secret key
     * @param value the string to encrypt
     * @return encrypted value as string
     */
	public String encrypt(String key, String value) {
		if(StringUtils.isNotEmpty(value)) {
			return wrapEx(() -> this.encrypt(key, value.getBytes(StandardCharsets.UTF_8)));
		}
		return null;
	}

    /**
     * encrypt bytes
     * @param key the secret key
     * @param value the bytes to encrypt
     * @return encrypted value as string
     */
	public String encrypt(String key, byte[] value) {
		try {
			
			byte[] initVector = new byte[IV_VECTOR_LENGTH];
			ThreadLocalRandom.current().nextBytes(initVector);
			
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec keySpec = new SecretKeySpec(this.generateKey(key), ALGORITHM_AES);

			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

			byte[] encrypted = cipher.doFinal(value);
			
			// prepend the iv to the encrypted message
			encrypted = ArrayUtils.addAll(iv.getIV(), encrypted);

			return Base64.encodeBase64String(encrypted);
		} catch (Exception ex) {
			logger.error("Could not perform encryption: {}", ex.getMessage(), ex);
		}

		return null;
	}

    /**
     * decrypt as string
     * @param key the secret key
     * @param encrypted the encrypted payload
     * @return decrypted value as string
     */
	public String decryptAsString(String key, String encrypted) {
		if(StringUtils.isNotEmpty(encrypted)) {
			return wrapEx(() -> new String(this.decrypt(key, encrypted)));
		}
		return null;
		
	}

    /**
     * decrypt as string
     * @param key the secret key
     * @param encrypted the encrypted payload
     * @return decrypted value as byte[]
     */
	public byte[] decrypt(String key, String encrypted) {
		return this.decrypt(key, Base64.decodeBase64(encrypted));
	}

    /**
     * decrypt as string
     * @param key the secret key
     * @param encrypted the encrypted payload
     * @return decrypted value as byte[]
     */
	public byte[] decrypt(String key, byte[] encrypted) {
		try {
			
			byte[] ivAndEncrypted = encrypted;
			byte[] initVector = Arrays.copyOf(ivAndEncrypted, IV_VECTOR_LENGTH);
			byte[] encryptionPayload = Arrays.copyOfRange(ivAndEncrypted, IV_VECTOR_LENGTH, ivAndEncrypted.length);
			
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec keySpec = new SecretKeySpec(this.generateKey(key), ALGORITHM_AES);

			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
			
			byte[] original = cipher.doFinal(encryptionPayload);

			return original;
		} catch (Exception ex) {
			logger.error("Could not perform decryption: {}", ex.getMessage(), ex);
		}
		return null;
	}

	private byte[] generateKey(String provided) {
		 return wrapEx(() -> {
			byte[] key = provided.getBytes(StandardCharsets.UTF_8);
			MessageDigest sha = MessageDigest.getInstance(ALGORITHM_SHA);
			key = sha.digest(key);
			// truncate or pad
			key = Arrays.copyOf(key, KEY_SIZE);
			return key;
		});
	}
}