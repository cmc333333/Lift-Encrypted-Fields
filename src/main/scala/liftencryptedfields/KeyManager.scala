package info.cmlubinski.liftencryptedfields

import java.io.FileInputStream
import java.security.KeyStore
import net.liftweb.util.Props
import net.liftweb.record.{OwnedField, Record}

object KeyManager {
  //  Search through env properties, fall back on Props
  private def getStr(key:String) = System.getProperty(key) match {
    case null => Props.get(key, "")
    case str => str
  }
  private lazy val pass = getStr("keymanager.pass")
  private lazy val keystore = {
    val ks = KeyStore.getInstance("JCEKS") //  required for symmetric keys
    ks.load(new FileInputStream(getStr("keymanager.file")), pass.toCharArray)
    ks
  }
  def getKey(alias:String) = keystore.getKey(alias, pass.toCharArray).getEncoded
}
trait HasKey {
  self:OwnedField[_ <: Record[_]] =>
  lazy val fieldKey = {
    val classname = owner.meta.getClass.getSimpleName.toLowerCase
    //  strip the $
    val recordName = classname.take(classname.length - 1)
    KeyManager.getKey(recordName + "." + name)
  }
}
