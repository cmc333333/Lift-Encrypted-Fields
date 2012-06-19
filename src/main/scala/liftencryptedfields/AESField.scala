package info.cmlubinski.liftencryptedfields

import java.security.SecureRandom
import net.liftweb.record.{OwnedField, Record}
import net.liftweb.common.Box
import net.liftweb.util.ControlHelpers.tryo
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}

trait AESField[OwnerType <: Record[OwnerType]] extends OwnedField[OwnerType] with HasKey {
  protected def binEncryptSet(plainText:Array[Byte]):OwnerType
  protected def binDecrypt():Box[Array[Byte]]
  protected def AESencrypt(plainText:Array[Byte]) = {
    val iv = new Array[Byte](32)
    new SecureRandom().nextBytes(iv)

    val encrypter = new GCMBlockCipher(new AESEngine())
    encrypter.init(true, new ParametersWithIV(new KeyParameter(fieldKey), iv))

    val output = new Array[Byte](encrypter.getOutputSize(plainText.length))
    val cipherLength = encrypter.processBytes(plainText, 0, plainText.length, output, 0)
    encrypter.doFinal(output, cipherLength)
    Array.concat(iv, output)
  }
  protected def AESdecrypt(cipherTextWithIV:Array[Byte]) = tryo {
    val iv = new Array[Byte](32)
    Array.copy(cipherTextWithIV, 0, iv, 0, 32)
    val cipherText = new Array[Byte](cipherTextWithIV.length - 32)
    Array.copy(cipherTextWithIV, 32, cipherText, 0, cipherTextWithIV.length - 32)

    val decrypter = new GCMBlockCipher(new AESEngine())
    decrypter.init(false, new ParametersWithIV(new KeyParameter(fieldKey), iv))
    val output = new Array[Byte](decrypter.getOutputSize(cipherText.length))
    val cipherLength = decrypter.processBytes(cipherText, 0, cipherText.length, output, 0)
    decrypter.doFinal(output, cipherLength);
    output
  }
}

trait TypedAESField[FieldType, OwnerType <: Record[OwnerType]] extends AESField[OwnerType] {
  def toBytes(data:FieldType):Array[Byte]
  def encryptSet(data:FieldType):OwnerType = binEncryptSet(toBytes(data))
  def <<<(data:FieldType) = encryptSet(data)

  def fromBytes(bytes:Array[Byte]):Box[FieldType]
  def decrypt():Box[FieldType] = binDecrypt.flatMap(pt => fromBytes(pt))
  def >>>() = decrypt()
  def decrypt_!():FieldType = decrypt.open_!
  def >>!() = decrypt_!
}
