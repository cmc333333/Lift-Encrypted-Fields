package info.cmlubinski.liftencryptedfields

import java.security.SecureRandom
import net.liftweb.common.Box
import net.liftweb.util.ControlHelpers.tryo
import net.liftweb.util.SecurityHelpers
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.engines.AESFastEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.EAXBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, AEADParameters}

object Utility {
  object Random {
    private var random = new SecureRandom()
    private var reseedAt = System.currentTimeMillis + 1000*60*60 // reseed once an hour
    def nextBytes(bytes:Array[Byte]) = {
      if (reseedAt < System.currentTimeMillis) {
        random = new SecureRandom()
        reseedAt = System.currentTimeMillis + 1000*60*60
      }
      random.nextBytes(bytes)
    }
  }

  def aesEncrypt(plainText:Array[Byte], key:Array[Byte]):Array[Byte] = aesEncrypt(plainText, key, None)
  def aesEncrypt(plainText:Array[Byte], key:Array[Byte], iv:Array[Byte]):Array[Byte] = 
    aesEncrypt(plainText, key, Some(iv))
  def aesEncrypt(plainText:Array[Byte], key:Array[Byte], _iv:Option[Array[Byte]]) = {
    val iv = _iv match {
      case Some(_iv) => _iv
      case None => {
        val iv = new Array[Byte](32)
        Random.nextBytes(iv)
        iv
      }
    }

    val encrypter = new EAXBlockCipher(new AESFastEngine())
    encrypter.init(true, new AEADParameters(new KeyParameter(key), 128, iv, Array[Byte]()))

    val output = new Array[Byte](encrypter.getOutputSize(plainText.length))
    val cipherLength = encrypter.processBytes(plainText, 0, plainText.length, output, 0)
    encrypter.doFinal(output, cipherLength)
    if (_iv.isDefined)
      output
    else
      Array.concat(iv, output)
  }
  def aesDecrypt(cipherTextWithIV:Array[Byte], key:Array[Byte]):Box[Array[Byte]] = tryo {
    val iv = new Array[Byte](32)
    Array.copy(cipherTextWithIV, 0, iv, 0, 32)
    val cipherText = new Array[Byte](cipherTextWithIV.length - 32)
    Array.copy(cipherTextWithIV, 32, cipherText, 0, cipherTextWithIV.length - 32)
    (cipherText, iv)
  }.flatMap{ case (cipherText, iv) => aesDecrypt(cipherText, iv, key) }
  def aesDecrypt(cipherText:Array[Byte], iv:Array[Byte], key:Array[Byte]) = tryo {
    val decrypter = new EAXBlockCipher(new AESFastEngine())
    decrypter.init(false, new AEADParameters(new KeyParameter(key), 128, iv, Array[Byte]()))
    val output = new Array[Byte](decrypter.getOutputSize(cipherText.length))
    val cipherLength = decrypter.processBytes(cipherText, 0, cipherText.length, output, 0)
    decrypter.doFinal(output, cipherLength);
    output
  }

  def hmac(plainText:Array[Byte], key:Array[Byte]) = {
    val macer = new HMac(new SHA512Digest())
    macer.init(new KeyParameter(key))
    macer.update(plainText, 0, plainText.length)

    val output = new Array[Byte](macer.getMacSize())
    macer.doFinal(output, 0)
    output
  }

  def pbkdf2(password:Array[Byte], iterationCount:Int = 10000) = {
    val salt = new Array[Byte](32)
    Random.nextBytes(salt)

    val generator = new PKCS5S2ParametersGenerator()
    generator.init(password, salt, iterationCount)
    Array.concat(salt, generator.generateDerivedParameters(512).asInstanceOf[KeyParameter].getKey)
  }
  def pbkdf2Cmp(guess:Array[Byte], stored:Array[Byte], iterationCount:Int = 10000) = {
    require (stored.length > 32, "stored not large enough")
    val salt = new Array[Byte](32)
    val hash = new Array[Byte](stored.length - 32)
    Array.copy(stored, 0, salt, 0, 32)
    Array.copy(stored, 32, hash, 0, stored.length - 32)
    val generator = new PKCS5S2ParametersGenerator()
    generator.init(guess, salt, iterationCount)
    SecurityHelpers.secureEquals(hash, generator.generateDerivedParameters(512).asInstanceOf[KeyParameter].getKey)
  }

}
