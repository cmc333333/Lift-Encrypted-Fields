package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.StringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
class NonNullDetHashField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends StringField(rec, 86) with DetHashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))) 
}

/**
 * DO NOT USE THIS FOR PASSWORDS. Instead, use pbkdf2.
 **/
class DetHashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends NonNullDetHashField[OwnerType](rec, systemKey) with TypedDetHashField[String, OwnerType]
  with StringConversion
