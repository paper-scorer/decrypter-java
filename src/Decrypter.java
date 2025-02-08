import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Decrypter {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new Exception("Expecting two arguments to be present.");
        }

        String password = args[0];
        String payload = args[1];

        String decryptedPayload = decryptText(password, payload);

        System.out.println(decryptedPayload);
        System.exit(0);
    }

    static String decryptText(String password, String payload) {
        String ivParamAsBase64 = payload.substring(0, 24);
        String saltAsBase64 = payload.substring(24, 52);
        String cipherTextAsBase64 = payload.substring(52);

        byte[] byteSalt = Base64.decodeBase64(saltAsBase64);
        byte[] bytePassword = password.getBytes();

        byte[] byteKey = new byte[byteSalt.length + bytePassword.length];
        System.arraycopy(bytePassword, 0, byteKey, 0, bytePassword.length);
        System.arraycopy(byteSalt, 0, byteKey, bytePassword.length, byteSalt.length);
        byte[] byteSecret = null;
        try {
            byteSecret = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(byteKey), 16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(byteSecret, "AES");

        byte[] byteIvParam = Base64.decodeBase64(ivParamAsBase64);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(byteIvParam);

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        byte[] byteCipherText = Base64.decodeBase64(cipherTextAsBase64);

        byte[] byteDecryptedText = null;
        try {
            byteDecryptedText = cipher.doFinal(byteCipherText);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        final String decryptedText = new String(byteDecryptedText);

        return decryptedText;
    }
}
