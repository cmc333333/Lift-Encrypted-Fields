package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.OptionalBinaryField
import net.liftweb.record.Record
import net.liftweb.common.{Box, Empty}

class OptionalAESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends OptionalBinaryField(rec)
  with AESField[OwnerType] {
  def binEncryptSet(plainText:Array[Byte]) = apply(Some(Utility.aesEncrypt(plainText, fieldKey)))
  def binDecrypt() = get match {
    case None => Empty
    case Some(value) => Utility.aesDecrypt(value, fieldKey)
  }
}
class OptionalAESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends OptionalAESField[OwnerType](rec)
  with StringConversion with TypedAESField[String, OwnerType]
class OptionalAESEnumField[OwnerType <: Record[OwnerType], EnumType <: Enumeration](rec:OwnerType, 
  override val enumRef:EnumType) extends OptionalAESField[OwnerType](rec) with EnumConversion[EnumType]
  with TypedAESField[EnumType#Value, OwnerType]
