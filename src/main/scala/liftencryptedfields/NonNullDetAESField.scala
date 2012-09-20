package info.cmlubinski.liftencryptedfields

import net.liftweb.common.Box
import net.liftweb.record.field.StringField
import net.liftweb.record.Record
import net.liftweb.util.SecurityHelpers

class NonNullDetAESField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val iv:Array[Byte])
  extends StringField(rec, 100000) with DetAESField[OwnerType] with StringAsBinary[OwnerType] {
  def binEncrypt(plainText:Array[Byte]) = Utility.aesEncrypt(plainText, fieldKey, iv)
  def binEncryptSet(plainText:Array[Byte]) = apply(Utility.aesEncrypt(plainText, fieldKey, iv))
  def binDecrypt() = Utility.aesDecrypt(getAsBin, iv, fieldKey)
}

/**
 * Only use for unique fields (e.g. user ids, email addresses)
 **/
class DetAESStringField[OwnerType <: Record[OwnerType]](rec:OwnerType, override val iv:Array[Byte])
  extends NonNullDetAESField[OwnerType](rec, iv) with TypedDetAESField[String, OwnerType] with StringConversion
