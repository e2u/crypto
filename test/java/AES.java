import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.print.DocFlavor.STRING;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;



public class AES {


	private static SecretKeySpec secretKey;
	private static byte[] key;
  private static byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	private static String decryptedString;
	private static String encryptedString;


	public static void setKey(String myKey) {
		MessageDigest sha = null;
    try {
      key = myKey.getBytes("UTF-8");
      secretKey = new SecretKeySpec(key, "AES");
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
	}

	public static String getDecryptedString() {
		return decryptedString;
	}

	public static void setDecryptedString(String decryptedString) {
		AES.decryptedString = decryptedString;
	}

	public static String getEncryptedString() {
		return encryptedString;
	}

	public static void setEncryptedString(String encryptedString) {
		AES.encryptedString = encryptedString;
	}

	public static byte[] ecb_encrypt(byte[] src) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] ecb_decrypt(byte[] src) {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}
  
  
	public static byte[] cbc_encrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] cbc_decrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] cfb_encrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] cfb_decrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}
  
  
	public static byte[] ofb_encrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] ofb_decrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] ctr_encrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static byte[] ctr_decrypt(byte[] src) {
		try {
      IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey,ivspec);
      return cipher.doFinal(src);
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}


	public static void main(String args[]) {
		final String strToEncrypt = "BEGIN---1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ---END";
		final String strPssword = "12345678901234567890123456789012";
		AES.setKey(strPssword);
    byte[] ent;
    byte[] dnt;
    
    ent = ecb_encrypt(strToEncrypt.getBytes());
    System.out.println("ecb 加密密文: "+Hex.encodeHexString(ent));
    dnt = ecb_decrypt(ent);
    System.out.println("ecb 解密明文: "+new String(dnt));
    

    ent = cbc_encrypt(strToEncrypt.getBytes());
    System.out.println("cbc 加密密文: "+Hex.encodeHexString(ent));
    dnt = cbc_decrypt(ent);
    System.out.println("cbc 解密明文: "+new String(dnt));
    
    
    ent = cfb_encrypt(strToEncrypt.getBytes());
    System.out.println("cfb 加密密文: "+Hex.encodeHexString(ent));
    dnt = cfb_decrypt(ent);
    System.out.println("cfb 解密明文: "+new String(dnt));
    
    ent = ofb_encrypt(strToEncrypt.getBytes());
    System.out.println("ofb 加密密文: "+Hex.encodeHexString(ent));
    dnt = ofb_decrypt(ent);
    System.out.println("ofb 解密明文: "+new String(dnt));
    
    
    ent = ctr_encrypt(strToEncrypt.getBytes());
    System.out.println("ctr 加密密文: "+Hex.encodeHexString(ent));
    dnt = ctr_decrypt(ent);
    System.out.println("ctr 解密明文: "+new String(dnt));

	}

}