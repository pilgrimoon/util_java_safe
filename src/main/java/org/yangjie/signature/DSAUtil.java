package org.yangjie.signature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * 数字签名DSA
 * @author YangJie [2017年10月10日 下午3:58:10]
 */
public class DSAUtil {
	public static HashMap<User, KeyPair> keyMap;

	/**
	 * 签名
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static String sign(String data, PrivateKey privateKey) throws Exception {
		Signature signature = Signature.getInstance(KeyFactory.getInstance("DSA").getAlgorithm());
		signature.initSign(privateKey);
		signature.update(data.getBytes());
		return Base64.getEncoder().encodeToString(signature.sign());
	}

	/**
	 * 验证
	 * @param data
	 * @param sign
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(String data, String sign, PublicKey publicKey) throws Exception {
		byte[] bytes = Base64.getDecoder().decode(sign);
		Signature signature = Signature.getInstance(KeyFactory.getInstance("DSA").getAlgorithm());
		signature.initVerify(publicKey);
		signature.update(data.getBytes());
		return signature.verify(bytes);
	}

	/**
	 * 生成密钥对
	 * @return
	 * @throws Exception
	 */
	public static KeyPair genKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(1024);
		return keyPairGenerator.generateKeyPair();
	}
	/**
     	* 对文件进行验证
     	*
     	* @param filePath
     	* @param sign
     	* @param publicKey
     	* @return
     	* @throws Exception
     	*/
	public static boolean verifyFile(String filePath, String sign, PublicKey publicKey) throws Exception {
	        //获取pdf文件的md5值 data=md5(file)
	        File file = new File(filePath);
	        String data = DigestUtils.md5Hex(FileUtils.readFileToByteArray(file));
	        byte[] bytes = Base64.getDecoder().decode(sign); //对数字签名进行解密 获得数据的Byte信息哈希值
	        Signature signature = Signature.getInstance(KeyFactory.getInstance("DSA").getAlgorithm());
	        //返回实现指定签名算法的 Signature 对象。
	        //KeyFactory是一个引擎类，可用于在公钥对象和私钥对象之间进行转换，并在其外部表示（可轻松传输）和内部表示之间转换密钥。
	        signature.initVerify(publicKey); //公钥验证
	        signature.update(data.getBytes()); //获取数据的Byte信息的哈希值
	        return signature.verify(bytes);
	    }

	/**
	* 通过id对文件进行验证（获取公钥）
	*
	* @param filePath
	* @param user
	* @param sign
	* @return
	* @throws Exception
	*/
	public static boolean verifyFileById(String filePath, User user, String sign) throws Exception {
	        //获取pdf文件的md5值 data=md5(file)
	        File file = new File(filePath);
	        String data = DigestUtils.md5Hex(FileUtils.readFileToByteArray(file));
	        byte[] bytes = Base64.getDecoder().decode(sign); //对数字签名进行解密 获得数据的Byte信息哈希值
	        Signature signature = Signature.getInstance(KeyFactory.getInstance("DSA").getAlgorithm());
	        signature.initVerify(keyMap.get(user).getPublic());
	        signature.update(data.getBytes());
	        return signature.verify(bytes);
	    }

	
    	/**
     	* 通过文件和用户名对文件md5值进行签名
     	*
     	* @param filePath
     	* @param user
     	* @return
     	* @throws Exception
     	*/
   	 public static String signById(String filePath, User user) throws Exception {
	        //获取pdf文件的md5值 data=md5(file)
	        File file = new File(filePath);
	        String data = DigestUtils.md5Hex(FileUtils.readFileToByteArray(file));
	        Signature signature = Signature.getInstance(KeyFactory.getInstance("DSA").getAlgorithm());
	        signature.initSign(keyMap.get(user).getPrivate()); //私钥初始化签名
	        signature.update(data.getBytes()); //获取数据的Byte信息的哈希值
	        return Base64.getEncoder().encodeToString(signature.sign());
	}


    	/**
     	* 获取公钥 跨语言调用jar包调功能
     	*
     	* @param keyPair
     	* @return
     	*/
    	public static PublicKey getPublicKey(KeyPair keyPair) {
        	PublicKey publicKey = keyPair.getPublic(); //通过getPublic获取公钥
        	return publicKey;
    	}


    	/**
     	* 获取私钥 跨语言调用jar包调功能
     	*
     	* @param keyPair
     	* @return
     	*/
    	public static PrivateKey getPrivateKey(KeyPair keyPair) {
	        PrivateKey privateKey = keyPair.getPrivate(); //通过getPublic获取公钥
        	return privateKey;
    	}

   	 /**
    	 * 公钥转String类型存储数据库
    	 *	
    	 * @param keyPair
   	  * @return
   	  */
   	public static String publicKeyToString(KeyPair keyPair) {
     	   	PublicKey publicKey = keyPair.getPublic(); //通过getPublic获取公钥
      	  	byte[] bytePublicKey = publicKey.getEncoded();
        	String stringPublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
        	return stringPublicKey;
    	}

    	/**
     	* 数据库提取String转公钥
     	*
     	* @param stringPublicKey
     	* @return
     	* @throws NoSuchAlgorithmException
     	* @throws InvalidKeySpecException
     	*/
    	public static PublicKey StringToPublicKey(String stringPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        	byte[] BytePublicKey = Base64.getDecoder().decode(stringPublicKey);
        	X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(BytePublicKey);
        	PublicKey publicKey = KeyFactory.getInstance("DSA").generatePublic(encodedKeySpec);
        	return publicKey;
    	}

    	/**
     	* 私钥转String类型存储文件
     	*
     	* @param keyPair
     	* @return
     	* @throws Exception
     	*/
    	public static String privateKeyToString(KeyPair keyPair) throws Exception{
        	PrivateKey privateKey = keyPair.getPrivate(); //通过getPublic获取公钥
        	return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    	}

    	/**
     	* 提取String转私钥
     	*
     	* @param stringPrivateKey
     	* @return
     	* @throws NoSuchAlgorithmException
     	* @throws InvalidKeySpecException
     	*/
    	public static PrivateKey StringToPrivateKey(String stringPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        	byte[] BytePrivateKey = Base64.getDecoder().decode(stringPrivateKey);
        	PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(BytePrivateKey);
        	PrivateKey privateKey = KeyFactory.getInstance("DSA").generatePrivate(pkcs8EncodedKeySpec);
        	return privateKey;
    	}	

	public static void main(String[] args) throws Exception {

		String data = "hello world";
		
		KeyPair keyPair = genKeyPair();

		// 获取公钥，并以base64格式打印出来
		PublicKey publicKey = keyPair.getPublic();
		System.out.println("公钥：" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

		// 获取私钥，并以base64格式打印出来
		PrivateKey privateKey = keyPair.getPrivate();
		System.out.println("私钥：" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

		// 签名
		String sign = sign(data, privateKey);
		System.out.println("签名：" + sign);

		// 验证
		boolean flag = verify(data, sign, publicKey);
		System.out.println("验证：" + flag);
		
	}
	
	
}
