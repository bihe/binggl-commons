package net.binggl.commons.crypto;

import static net.binggl.commons.util.ExceptionHelper.wrapEx;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AesEncryption {
	
	private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5PADDING"; 
	private static final String ENCODING = "UTF-8";
	private static final String ALGORITHM_AES = "AES";
	private static final String ALGORITHM_SHA = "SHA-256";
	private static final Logger logger = LoggerFactory.getLogger(AesEncryption.class);
	private static final int IV_VECTOR_LENGHT = 16;
	
	
	public AesEncryption() {
	}
	
	public String encrypt(String key, String value) {
		try {
			
			byte[] initVector = new byte[IV_VECTOR_LENGHT];
			ThreadLocalRandom.current().nextBytes(initVector);
			
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec skeySpec = new SecretKeySpec(this.generateKey(key), ALGORITHM_AES);

			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			
			// prepend the iv to the encrypted message
			encrypted = ArrayUtils.addAll(iv.getIV(), encrypted);

			return Base64.encodeBase64String(encrypted);
		} catch (Exception ex) {
			logger.error("Could not perform encryption: {}", ex.getMessage(), ex);
		}

		return null;
	}

	public String decrypt(String key, String encrypted) {
		try {
			
			byte[] ivAndEncrypted = Base64.decodeBase64(encrypted);
			byte[] initVector = Arrays.copyOf(ivAndEncrypted, IV_VECTOR_LENGHT);
			byte[] encryptionPaylod = Arrays.copyOfRange(ivAndEncrypted, IV_VECTOR_LENGHT, ivAndEncrypted.length);
			
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec skeySpec = new SecretKeySpec(this.generateKey(key), ALGORITHM_AES);

			Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			
			byte[] original = cipher.doFinal(encryptionPaylod);

			return new String(original);
		} catch (Exception ex) {
			logger.error("Could not perform decryption: {}", ex.getMessage(), ex);
		}

		return null;
	}

	
	private byte[] generateKey(String provided) {
		 return wrapEx(() -> {
			byte[] key = provided.getBytes(ENCODING);
			MessageDigest sha = MessageDigest.getInstance(ALGORITHM_SHA);
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			return key;
		});
	}
	
	
//	public static void main(String[] args) {
//		String key = "Bar12345Bar12345"; // 128 bit key
//		String initVector = "RandomInitVector"; // 16 bytes IV
//
//		System.out.println(decrypt(key, initVector, encrypt(key, initVector, "Hello World")));
//	}
}