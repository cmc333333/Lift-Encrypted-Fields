package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.OptionalStringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
abstract class OptionalHashField[OwnerType <: Record[OwnerType]](rec:OwnerType) extends OptionalStringField(rec, 86)
  with HashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(Some(
    SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))
  ))
}
abstract class OptionalHashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType) 
  extends OptionalHashField[OwnerType](rec) with StringConversion
