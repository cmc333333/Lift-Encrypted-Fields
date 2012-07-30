package info.cmlubinski.liftencryptedfields

import java.nio.ByteBuffer
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
trait IntConversion extends TypedConversion[Int] {
  //  all ints in the JVM are 4 bytes = 32 bits
  def toBytes(data:Int) = ByteBuffer.allocate(4).putInt(data).array()
  def fromBytes(bytes:Array[Byte]) = tryo { ByteBuffer.wrap(bytes).getInt }
}
trait LongConversion extends TypedConversion[Long] {
  //  all ints in the JVM are 8 bytes = 64 bit
  def toBytes(data:Long) = ByteBuffer.allocate(8).putLong(data).array()
  def fromBytes(bytes:Array[Byte]) = tryo { ByteBuffer.wrap(bytes).getLong }
}
