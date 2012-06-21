package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.BinaryField
import net.liftweb.record.Record
import net.liftweb.common.Box

class NonNullAESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends BinaryField(rec) 
  with AESField[OwnerType] {
  def binEncryptSet(plainText:Array[Byte]) = apply(AESencrypt(plainText))
  def binDecrypt() = AESdecrypt(get)
}
class AESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends NonNullAESField[OwnerType](rec)
  with StringTypedAESField[OwnerType]

class AESEnumField[OwnerType <: Record[OwnerType], EnumType <: Enumeration](rec:OwnerType, 
  override val enumRef:EnumType) extends NonNullAESField[OwnerType](rec) with EnumTypedAESField[OwnerType, EnumType]
