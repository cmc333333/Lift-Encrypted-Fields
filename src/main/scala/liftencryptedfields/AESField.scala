package info.cmlubinski.liftencryptedfields

import java.security.SecureRandom
import net.liftweb.record.field.BinaryField
import net.liftweb.record.{MetaRecord, Record}
import net.liftweb.util.ControlHelpers.tryo
import net.liftweb.common.Box
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}


object Ex {
  def apply() {
    val e = E.createRecord
    e.name <<< "hello, how are you?"
    println(e.name.>>!)
  }
}
private class E extends Record[E] {
  override def meta = E

  val name = new AESStringField(this)
}
private object E extends E with MetaRecord[E]
class AESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends BinaryField(rec) with HasKey {
  def binEncryptSet(plainText:Array[Byte]) = {
    val iv = new Array[Byte](32)
    new SecureRandom().nextBytes(iv)

    val encrypter = new GCMBlockCipher(new AESEngine())
    encrypter.init(true, new ParametersWithIV(new KeyParameter(fieldKey), iv))

    val output = new Array[Byte](encrypter.getOutputSize(plainText.length))
    val cipherLength = encrypter.processBytes(plainText, 0, plainText.length, output, 0)
    encrypter.doFinal(output, cipherLength)
    apply(Array.concat(iv, output))
  }
  def binDecrypt() = tryo {
    val iv = new Array[Byte](32)
    Array.copy(get, 0, iv, 0, 32)
    val cipherText = new Array[Byte](get.length - 32)
    Array.copy(get, 32, cipherText, 0, get.length - 32)

    val decrypter = new GCMBlockCipher(new AESEngine())
    decrypter.init(false, new ParametersWithIV(new KeyParameter(fieldKey), iv))
    val output = new Array[Byte](decrypter.getOutputSize(cipherText.length))
    val cipherLength = decrypter.processBytes(cipherText, 0, cipherText.length, output, 0)
    decrypter.doFinal(output, cipherLength);
    output
  }
}
abstract class TypedAES[FieldType, OwnerType <: Record[OwnerType]](rec:OwnerType) extends AESField[OwnerType](rec) {
  def toBytes(data:FieldType):Array[Byte]
  def encryptSet(data:FieldType):OwnerType = binEncryptSet(toBytes(data))
  def <<<(data:FieldType) = encryptSet(data)

  def fromBytes(bytes:Array[Byte]):Box[FieldType]
  def decrypt():Box[FieldType] = binDecrypt.flatMap(pt => fromBytes(pt))
  def >>>() = decrypt()
  def decrypt_!():FieldType = decrypt.open_!
  def >>!() = decrypt_!
}
class AESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends TypedAES[String, OwnerType](rec) {
  def toBytes(data:String) = data.getBytes("UTF-8")
  def fromBytes(bytes:Array[Byte]) = tryo { new String(bytes, "UTF-8") }
}
