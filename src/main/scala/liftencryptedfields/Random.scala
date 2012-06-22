package info.cmlubinski.liftencryptedfields

import java.security.SecureRandom

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
