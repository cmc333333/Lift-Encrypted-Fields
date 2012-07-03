package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.OptionalStringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
class OptionalHashField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends OptionalStringField(rec, 86) with HashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(Some(
    SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))
  ))
}
class OptionalHashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends OptionalHashField[OwnerType](rec, systemKey) with StringConversion
