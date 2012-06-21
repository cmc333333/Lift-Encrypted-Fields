package info.cmlubinski.liftencryptedfields

import net.liftweb.record.Record
import net.liftweb.util.ControlHelpers.tryo

trait StringTypedAESField[OwnerType <: Record[OwnerType]] extends TypedAESField[String, OwnerType] {
  def toBytes(data:String) = data.getBytes("UTF-8")
  def fromBytes(bytes:Array[Byte]) = tryo { new String(bytes, "UTF-8") }
}
trait EnumTypedAESField[OwnerType <: Record[OwnerType], EnumType <: Enumeration]
  extends TypedAESField[EnumType#Value, OwnerType] {
  protected val enumRef:EnumType
  def toBytes(data:EnumType#Value) = Array[Byte](data.id.toByte)
  def fromBytes(bytes:Array[Byte]) = tryo { enumRef(bytes(0).toInt) }
}
