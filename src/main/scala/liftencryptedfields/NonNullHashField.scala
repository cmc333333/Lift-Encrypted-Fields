package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.StringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
abstract class NonNullHashField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends StringField(rec, 86)
  with HashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))) 
}

abstract class HashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends NonNullHashField[OwnerType](rec)
  with StringConversion
