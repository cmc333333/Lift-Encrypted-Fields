package info.cmlubinski.liftencryptedfields

import net.liftweb.record.{OwnedField, Record}
import net.liftweb.util.SecurityHelpers

trait HashField[OwnerType <: Record[OwnerType]] extends OwnedField[OwnerType] with HasKey {
  protected def systemKey:Array[Byte]
  protected def binHash_?(plainText:Array[Byte]) = Utility.hmac(plainText, Array.concat(fieldKey, systemKey))
  protected def binHashSet(plainText:Array[Byte]):OwnerType
}

trait TypedHashField[FieldType, OwnerType <: Record[OwnerType]] extends HashField[OwnerType] 
  with TypedConversion[FieldType] {
  def hashSet(data:FieldType):OwnerType = binHashSet(toBytes(data))
  def <<<(data:FieldType) = hashSet(data)

  def hash_?(data:FieldType) = SecurityHelpers.base64EncodeURLSafe(binHash_?(toBytes(data)))
  def <<?(data:FieldType) = hash_?(data)
}
