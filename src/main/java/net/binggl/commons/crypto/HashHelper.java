package net.binggl.commons.crypto;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * static helper methods
 * @author henrik
 */
public class HashHelper {

	/**
	 * create hash value for the given parameters
	 * @param params a list of String params
	 * @return a combination of the parameters as a key
	 */
	public static String getSHA(String... params) {
		if (params != null && params.length > 0) {
			StringBuffer buffer = new StringBuffer();
			for (int i = 0; i < params.length; i++) {
				if (i > 0)
					buffer.append("|");
				buffer.append(params[i]);
			}
			return DigestUtils.sha256Hex(buffer.toString());
		}
		return null;
	}
}