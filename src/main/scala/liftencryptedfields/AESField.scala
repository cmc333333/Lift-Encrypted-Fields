package info.cmlubinski.liftencryptedfields

import java.security.SecureRandom
import net.liftweb.record.field.BinaryField
import net.liftweb.record.{MetaRecord, Record}
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}


object Ex {
  def apply() {
    val e = E.createRecord
    val pt = "hello, how are you?".getBytes("UTF-8")
    e.name.binEncryptSet(pt)
    e.name.binDecrypt()
  }
}
private class E extends Record[E] {
  override def meta = E

  val name = new AESField(this)
}
private object E extends E with MetaRecord[E]
private class AESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends BinaryField(rec) {
  def binEncryptSet(plainText:Array[Byte]) = {
    val iv = new Array[Byte](32)
    new SecureRandom().nextBytes(iv)

    val encrypter = new GCMBlockCipher(new AESEngine())
    encrypter.init(true, new ParametersWithIV(new KeyParameter(KeyManager.getKey("a.a")), iv))

    val output = new Array[Byte](encrypter.getOutputSize(plainText.length))
    val cipherLength = encrypter.processBytes(plainText, 0, plainText.length, output, 0)
    encrypter.doFinal(output, cipherLength)
    apply(Array.concat(iv, output))
  }
  def binDecrypt() = {
    val iv = new Array[Byte](32)
    Array.copy(get, 0, iv, 0, 32)
    val cipherText = new Array[Byte](get.length - 32)
    Array.copy(get, 32, cipherText, 0, get.length - 32)

    val decrypter = new GCMBlockCipher(new AESEngine())
    decrypter.init(false, new ParametersWithIV(new KeyParameter(KeyManager.getKey("a.a")), iv))
    val output = new Array[Byte](decrypter.getOutputSize(cipherText.length))
    val cipherLength = decrypter.processBytes(cipherText, 0, cipherText.length, output, 0)
    decrypter.doFinal(output, cipherLength);
    output
  }
}
