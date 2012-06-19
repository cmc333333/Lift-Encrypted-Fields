package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.OptionalBinaryField
import net.liftweb.record.Record
import net.liftweb.common.{Box, Empty}

class OptionalAESField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends OptionalBinaryField(rec)
  with AESField[OwnerType] {
  def binEncryptSet(plainText:Array[Byte]) = apply(Some(AESencrypt(plainText)))
  def binDecrypt() = get match {
    case None => Empty
    case Some(value) => AESdecrypt(value)
  }
}
class OptionalAESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends OptionalAESField[OwnerType](rec)
  with StringTypedAESField[OwnerType]
