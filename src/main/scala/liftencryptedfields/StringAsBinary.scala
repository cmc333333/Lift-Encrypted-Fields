package info.cmlubinski.liftencryptedfields

import net.liftweb.record.Record
import net.liftweb.record.field.StringField
import net.liftweb.util.SecurityHelpers

trait StringAsBinary[OwnerType <: Record[OwnerType]] {
  self:StringField[OwnerType] =>
  def getAsBin() = SecurityHelpers.base64Decode(get)
  def apply(bin:Array[Byte]):OwnerType = apply(SecurityHelpers.base64EncodeURLSafe(bin))
}
