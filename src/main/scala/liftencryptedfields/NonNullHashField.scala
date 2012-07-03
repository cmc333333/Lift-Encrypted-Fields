package info.cmlubinski.liftencryptedfields

import net.liftweb.record.field.StringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

//  86 = Ceil(512 (hash output) / 6 (base64 bits))
class NonNullHashField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends StringField(rec, 86) with HashField[OwnerType] {
  protected def binHashSet(plainText:Array[Byte]) = apply(SecurityHelpers.base64EncodeURLSafe(binHash_?(plainText))) 
}

/**
 * DO NOT USE THIS FOR PASSWORDS. Instead, use pbkdf2.
 **/
class HashStringField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val systemKey:Array[Byte]) 
  extends NonNullHashField[OwnerType](rec, systemKey) with StringConversion
