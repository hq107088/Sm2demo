package com.hq.test.sm2.bcplib;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;


import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import cn.hutool.crypto.SecureUtil;

public class Sm2lib {

	public static void main(String[] args) {
		//私钥:8cd385a72cb6e6e5b726b7b00a4149a8ff2b820d6226515f0edc7db31b4b20bb
//		公钥:04321ce3dc8b6c271cfc30d215ab15aab05fa23db68c3a469cf27a66ce483db54291794cb71ea6414706d931027c141f5c584bf57ab9eb9d9d0532301495b9220a

		// TODO Auto-generated method stub
		/*X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
		ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
		ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
		try {
			keyPairGenerator.init(new ECKeyGenerationParameters(domainParameters, SecureRandom.getInstance("SHA1PRNG")));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();

		//私钥，16进制格式，自己保存，格式如a2081b5b81fbea0b6b973a3ab6dbbbc65b1164488bf22d8ae2ff0b8260f64853
		BigInteger privatekey = ((ECPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate()).getD();
		String privateKeyHex = privatekey.toString(16);
		System.out.println("私钥:"+privateKeyHex);

		//公钥，16进制格式，发给前端，格式如04813d4d97ad31bd9d18d785f337f683233099d5abed09cb397152d50ac28cc0ba43711960e811d90453db5f5a9518d660858a8d0c57e359a8bf83427760ebcbba
		ECPoint ecPoint = ((ECPublicKeyParameters) asymmetricCipherKeyPair.getPublic()).getQ();
		byte[] ddd = ecPoint.getEncoded(false);
		String publicKeyHex = Hex.toHexString(ddd);
		byte[] ppp = ByteUtils.fromHexString(publicKeyHex);
		System.out.println("公钥:"+publicKeyHex);*/
//		decode();
		encode();
//		test();
	}

	public static void decode(){
		String cipherData = "0429199dcdfaadf06d1963a11988ab55cb7e03c81dbe5c9086b9f83347e7d0dcd57c96c63774c8850bd1994810e5f2f58d61073e6cadfd7cd1a8e70e8d57d8417d18a91ae36dd4945965f611747748e9f5023f330846c42365e56acfff0026e755e421787c1601c1672771";
		byte[] cipherDataByte = Hex.decode(cipherData);

		//刚才的私钥Hex，先还原私钥
		String privateKey = "8cd385a72cb6e6e5b726b7b00a4149a8ff2b820d6226515f0edc7db31b4b20bb";
		BigInteger privateKeyD = new BigInteger(privateKey, 16);
		X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
		ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
		
		ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

		//用私钥解密
		SM2Engine sm2Engine = new SM2Engine();
		sm2Engine.init(false, privateKeyParameters);

		//processBlock得到Base64格式，记得解码
		byte[] arrayOfBytes;
		try {
//			byte[] dd = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
//			arrayOfBytes = Base64.getDecoder().decode(dd);
			arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
			//得到明文：SM2 Encryption Test
			String data = new String(arrayOfBytes);
			System.out.println(data);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static void encode(){
		//刚才的私钥Hex，先还原私钥
		String publicKey = "04321ce3dc8b6c271cfc30d215ab15aab05fa23db68c3a469cf27a66ce483db54291794cb71ea6414706d931027c141f5c584bf57ab9eb9d9d0532301495b9220a";
		byte[] bb = ByteUtils.fromHexString(publicKey);
		String plaintext = "hello word";
		 // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        //提取公钥点
        ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(publicKey));
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
 
        SM2Engine sm2Engine = new SM2Engine();
         // 设置sm2为加密模式
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
 
        byte[] arrayOfBytes = null;
        try {
            byte[] in = plaintext.getBytes();
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
            System.out.println(Hex.toHexString(arrayOfBytes));
        } catch (Exception e) {
        }
	}
	
	
	public static void test(){
		String cipherData = "04f37d1bc42abfd90cf3d1d0ea6fbde3bed1e6264a7127c62f98e71517429e09cb59879c35d8205f51b991ce8271371d7bcb0a38bf1927a6e539bd822bbd9996df4ef4f7acd11d2686151a27902b91f0b61a3955ea0cf17c5d2aa0401989fb611ddd438c0ff7d77af9601e5785ebca08be";
		byte[] cipherDataByte = Hex.decode(cipherData);

		//刚才的私钥Hex，先还原私钥
		String privateKey = "046821e15e8809da6a1062421e37f0d05927a9e0605f46c5501381d28e0250d5";
		BigInteger privateKeyD = new BigInteger(privateKey, 16);
		X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
		ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
		
		ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

		//用私钥解密
		SM2Engine sm2Engine = new SM2Engine();
		sm2Engine.init(false, privateKeyParameters);

		//processBlock得到Base64格式，记得解码
		byte[] arrayOfBytes;
		try {
			arrayOfBytes = Base64.getDecoder().decode(sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length));
			//得到明文：SM2 Encryption Test
			String data = new String(arrayOfBytes);
			System.out.println(data);
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
