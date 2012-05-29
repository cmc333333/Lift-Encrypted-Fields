package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.BinaryField
import net.liftweb.record.Record
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}


object Ex {
  def apply() {
    val key = Array[Byte](
    -67, -35, 2, -26, 29, 53, 43, -11, -66, -26, -111, 55, -41, 53, -54, 41, -80, 53, -59, 59, -102, 5, -7, 70, 72,
    16, -110, -83, -56, 5, -109, 69)
    val iv = key
    val encrypter = new GCMBlockCipher(new AESEngine())
    val params = new ParametersWithIV(new KeyParameter(key), iv)
    encrypter.init(true, params)
    
    val data = "Testing This".getBytes("UTF-8")
    val minSize = encrypter.getOutputSize(data.length)
    val outBuf = new Array[Byte](minSize)
    val length1 = encrypter.processBytes(data, 0, data.length, outBuf, 0);
    val length2 = encrypter.doFinal(outBuf, length1);
    val actualLength = length1 + length2
    val result = new Array[Byte](actualLength)
    System.arraycopy(outBuf, 0, result, 0, result.length)

    result(5) = 20
    val decrypter = new GCMBlockCipher(new AESEngine())
    decrypter.init(false, params)
    val minSize2 = decrypter.getOutputSize(result.length)
    val outBuf2 = new Array[Byte](minSize2)
    val length12 = decrypter.processBytes(result, 0, result.length, outBuf2, 0);
    val length22 = decrypter.doFinal(outBuf2, length12);
    val actualLength2 = length12 + length22
    val result2 = new Array[Byte](actualLength2)
    System.arraycopy(outBuf2, 0, result2, 0, result2.length)

    println(result2.toList)
    println(data.toList)
  }
}
/*
class AESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends BinaryField(rec) {
  def encrypt(
}
*/
