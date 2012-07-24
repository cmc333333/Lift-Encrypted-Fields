package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.BinaryField
import net.liftweb.record.Record
import net.liftweb.common.Box

class NonNullAESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends BinaryField(rec) 
  with AESField[OwnerType] {
  def binEncryptSet(plainText:Array[Byte]) = apply(Utility.aesEncrypt(plainText, fieldKey))
  def binDecrypt() = Utility.aesDecrypt(get, fieldKey)
}
class AESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends NonNullAESField[OwnerType](rec)
  with StringConversion with TypedAESField[String, OwnerType]

class AESEnumField[OwnerType <: Record[OwnerType], EnumType <: Enumeration](rec:OwnerType, 
  override val enumRef:EnumType) extends NonNullAESField[OwnerType](rec) with EnumConversion[EnumType] 
  with TypedAESField[EnumType#Value, OwnerType]

class AESIntField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends NonNullAESField[OwnerType](rec) 
  with IntConversion with TypedAESField[Int, OwnerType]
class AESLongField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends NonNullAESField[OwnerType](rec) 
  with LongConversion with TypedAESField[Long, OwnerType]
