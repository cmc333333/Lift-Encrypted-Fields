package info.cmlubinski.liftencryptedfields

import net.liftweb.record.Record
import net.liftweb.util.ControlHelpers.tryo

trait StringTypedAESField[OwnerType <: Record[OwnerType]] extends TypedAESField[String, OwnerType] {
  def toBytes(data:String) = data.getBytes("UTF-8")
  def fromBytes(bytes:Array[Byte]) = tryo { new String(bytes, "UTF-8") }
}
