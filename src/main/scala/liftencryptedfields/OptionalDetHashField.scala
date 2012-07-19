package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.OptionalStringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
class OptionalDetHashField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends OptionalStringField(rec, 86) with DetHashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(Some(
    SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))
  ))
}
class OptionalDetHashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends OptionalDetHashField[OwnerType](rec, systemKey) with TypedDetHashField[String, OwnerType]
  with StringConversion
