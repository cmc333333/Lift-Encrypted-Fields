package info.cmlubinski.liftencryptedfields

import java.io.FileInputStream
import java.security.KeyStore
import net.liftweb.util.Props

object KeyManager {
  /*
  private lazy val pass = Props.get("keymanager.pass", "")
  private lazy val keystore = {
    val ks = KeyStore.getInstance("JCEKS") //  required for symmetric keys
    ks.load(new FileInputStream(Props.get("keymanager.file", "")), pass.toCharArray)
    ks
  }
  def getKey(alias:String) = keystore.getKey(alias, pass.toCharArray).getEncoded
  */
  def getKey(alias:String) = Array[Byte]( -67, -35, 2, -26, 29, 53, 43, -11, -66, -26, -111, 55, -41, 53, -54, 41, 
    -80, 53, -59, 59, -102, 5, -7, 70, 72, 16, -110, -83, -56, 5, -109, 69)
}
