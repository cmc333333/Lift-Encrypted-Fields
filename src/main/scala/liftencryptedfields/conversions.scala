package info.cmlubinski.liftencryptedfields

import net.liftweb.record.Record
import net.liftweb.util.ControlHelpers.tryo
import net.liftweb.common.Box

trait TypedConversion[FieldType] {
  def toBytes(data:FieldType):Array[Byte]
  def fromBytes(bytes:Array[Byte]):Box[FieldType]
}
trait StringConversion extends TypedConversion[String] {
  def toBytes(data:String) = data.getBytes("UTF-8")
  def fromBytes(bytes:Array[Byte]) = tryo { new String(bytes, "UTF-8") }
}
trait EnumConversion[EnumType <: Enumeration] extends TypedConversion[EnumType#Value] {
  protected val enumRef:EnumType
  def toBytes(data:EnumType#Value) = Array[Byte](data.id.toByte)
  def fromBytes(bytes:Array[Byte]) = tryo { enumRef(bytes(0).toInt) }
}
