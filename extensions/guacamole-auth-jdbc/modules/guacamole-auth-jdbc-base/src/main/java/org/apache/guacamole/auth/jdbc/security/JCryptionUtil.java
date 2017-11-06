/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.auth.jdbc.security;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Ashwin Kumar
 * 
 */
public class JCryptionUtil {

	/**
	 * Constructor
	 */
	public JCryptionUtil() {
		java.security.Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Generates the Keypair with the given keyLength.
	 * 
	 * @param keyLength
	 *            length of key
	 * @return KeyPair object
	 * @throws RuntimeException
	 *             if the RSA algorithm not supported
	 */
	public KeyPair generateKeypair(int keyLength) {
		String privateKeyFilePath = System.getProperty("SWIFTUI_HOME")
				+ "/.swiftui/config/keys/login.private";
		String publicKeyFilePath = System.getProperty("SWIFTUI_HOME")
				+ "/.swiftui/config/keys/login.public";
		try {
			File privateKeyFile = new File(privateKeyFilePath);
			// Create directory if not exists
			privateKeyFile.getParentFile().mkdirs();

			if (privateKeyFile.exists()) {
				// Return key pair if already exists on disk

				PrivateKey privateKey = getPrivate(privateKeyFilePath);
				PublicKey publicKey = getPublic(publicKeyFilePath);

				return new KeyPair(publicKey, privateKey);
			}

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(keyLength);
			KeyPair keyPair = kpg.generateKeyPair();

			writeToFile(publicKeyFilePath, keyPair.getPublic().getEncoded());
			writeToFile(privateKeyFilePath, keyPair.getPrivate().getEncoded());

			/*
			 * KeyFactory keyFac = KeyFactory.getInstance("RSA"); try {
			 * RSAPrivateCrtKeySpec pkSpec = (RSAPrivateCrtKeySpec) keyFac
			 * .getKeySpec(keyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
			 * 
			 * System.out.println("Prime exponent p : " +
			 * byteArrayToHexString(pkSpec.getPrimeExponentP().toByteArray()));
			 * System.out.println("Prime exponent q : " +
			 * byteArrayToHexString(pkSpec.getPrimeExponentQ().toByteArray()));
			 * System.out.println("Modulus : " +
			 * byteArrayToHexString(pkSpec.getModulus().toByteArray()));
			 * System.out.println("Private exponent : " +
			 * byteArrayToHexString(pkSpec.getPrivateExponent().toByteArray()));
			 * System.out.println("Public exponent : " +
			 * byteArrayToHexString(pkSpec.getPublicExponent().toByteArray()));
			 * 
			 * } catch (InvalidKeySpecException e) { // TODO Auto-generated
			 * catch block e.printStackTrace(); }
			 */

			return keyPair;
		} catch (NoSuchAlgorithmException | IOException e) {
			throw new RuntimeException("RSA algorithm not supported", e);
		} catch (Exception e) {
			throw new RuntimeException("Other exception ", e);
		}
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
	/**
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	public PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
	/**
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	/**
	 * @param path
	 * @param key
	 * @throws IOException
	 */
	public void writeToFile(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();

		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}

	/**
	 * Decrypts a given string with the RSA keys
	 * 
	 * @param encrypted
	 *            full encrypted text
	 * @param keys
	 *            RSA keys
	 * @return decrypted text
	 * @throws RuntimeException
	 *             if the RSA algorithm not supported or decrypt operation
	 *             failed
	 */
	public static String decrypt(String encrypted, KeyPair keys) {
		Cipher dec;
		try {
			dec = Cipher.getInstance("RSA/NONE/NoPadding");
			dec.init(Cipher.DECRYPT_MODE, keys.getPrivate());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("RSA algorithm not supported", e);
		}
		String[] blocks = encrypted.split("\\s");
		StringBuffer result = new StringBuffer();
		try {
			for (int i = blocks.length - 1; i >= 0; i--) {
				byte[] data = hexStringToByteArray(blocks[i]);
				byte[] decryptedBlock = dec.doFinal(data);
				result.append(new String(decryptedBlock));
			}
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Decrypt error", e);
		}
		return result.reverse().toString();
	}

	/**
	 * Parse url string (Todo - better parsing algorithm)
	 * 
	 * @param url
	 *            value to parse
	 * @param encoding
	 *            encoding value
	 * @return Map with param name, value pairs
	 */
	@SuppressWarnings("unchecked")
	public static Map parse(String url, String encoding) {
		try {
			String urlToParse = URLDecoder.decode(url, encoding);
			String[] params = urlToParse.split("&");
			Map parsed = new HashMap();
			for (int i = 0; i < params.length; i++) {
				String[] p = params[i].split("=");
				String name = p[0];
				String value = (p.length == 2) ? p[1] : null;
				parsed.put(name, value);
			}
			return parsed;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Unknown encoding.", e);
		}
	}

	/**
	 * Return public RSA key modulus
	 * 
	 * @param keyPair
	 *            RSA keys
	 * @return modulus value as hex string
	 */
	public static String getPublicKeyModulus(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		return publicKey.getModulus().toString(16);
	}

	/**
	 * Return public RSA key exponent
	 * 
	 * @param keyPair
	 *            RSA keys
	 * @return public exponent value as hex string
	 */
	public static String getPublicKeyExponent(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		return publicKey.getPublicExponent().toString(16);
	}

	/**
	 * Max block size with given key length
	 * 
	 * @param keyLength
	 *            length of key
	 * @return numeber of digits
	 */
	public static int getMaxDigits(int keyLength) {
		return ((keyLength * 2) / 16) + 3;
	}

	/**
	 * Convert byte array to hex string
	 * 
	 * @param bytes
	 *            input byte array
	 * @return Hex string representation
	 */
	public static String byteArrayToHexString(byte[] bytes) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			result.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return result.toString();
	}

	/**
	 * Convert hex string to byte array
	 * 
	 * @param data
	 *            input string data
	 * @return bytes
	 */
	public static byte[] hexStringToByteArray(String data) {
		int k = 0;
		byte[] results = new byte[data.length() / 2];
		for (int i = 0; i < data.length();) {
			results[k] = (byte) (Character.digit(data.charAt(i++), 16) << 4);
			results[k] += (byte) (Character.digit(data.charAt(i++), 16));
			k++;
		}
		return results;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		JCryptionUtil jCryption = new JCryptionUtil();
		System.out.println(jCryption.toPublicKeyString());
	}

	private void generate(String publicKeyFilename, String privateFilename) {

		try {

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			// Create the public and private keys
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
					"BC");

			SecureRandom random = createFixedRandom();
			generator.initialize(1024, random);

			KeyPair pair = generator.generateKeyPair();
			Key pubKey = pair.getPublic();
			Key privKey = pair.getPrivate();

			System.out.println("publicKey : "
					+ Base64.encodeBase64String(pubKey.getEncoded()));
			System.out.println("privateKey : "
					+ Base64.encodeBase64String(privKey.getEncoded()));

			BufferedWriter out = new BufferedWriter(new FileWriter(
					publicKeyFilename));
			out.write(Base64.encodeBase64String(pubKey.getEncoded()));
			out.close();

			out = new BufferedWriter(new FileWriter(privateFilename));
			out.write(Base64.encodeBase64String(privKey.getEncoded()));
			out.close();

		} catch (Exception e) {
			System.out.println(e);
		}
	}

	public static SecureRandom createFixedRandom() {
		return new FixedRand();
	}

	private static class FixedRand extends SecureRandom {

		private static final long serialVersionUID = 1L;
		MessageDigest sha;
		byte[] state;

		FixedRand() {
			try {
				this.sha = MessageDigest.getInstance("SHA-1");
				this.state = sha.digest();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("can't find SHA-1!");
			}
		}

		public void nextBytes(byte[] bytes) {

			int off = 0;

			sha.update(state);

			while (off < bytes.length) {
				state = sha.digest();

				if (bytes.length - off > state.length) {
					System.arraycopy(state, 0, bytes, off, state.length);
				} else {
					System.arraycopy(state, 0, bytes, off, bytes.length - off);
				}

				off += state.length;

				sha.update(state);
			}
		}
	}

	/**
	 * @return
	 */
	public String toPublicKeyString() {
		KeyPair keys = generateKeypair(512);
		StringBuffer out = new StringBuffer();

		String e = getPublicKeyExponent(keys);
		String n = getPublicKeyModulus(keys);
		String md = String.valueOf(getMaxDigits(512));

		out.append("{\"e\":\"");
		out.append(e);
		out.append("\",\"n\":\"");
		out.append(n);
		out.append("\",\"maxdigits\":\"");
		out.append(md);
		out.append("\"}");

		return out.toString();
	}

	/**
	 * @param inputString
	 * @return
	 */
	public String MD5(String inputString) {
		try {
			java.security.MessageDigest md = java.security.MessageDigest
					.getInstance("MD5");
			byte[] array = md.digest(inputString.getBytes());
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < array.length; ++i) {
				sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100)
						.substring(1, 3));
			}
			return sb.toString();
		} catch (java.security.NoSuchAlgorithmException e) {
		}
		return null;
	}

}