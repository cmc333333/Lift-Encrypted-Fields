package info.cmlubinski.liftencryptedfields

import net.liftweb.record.{OwnedField, Record}
import net.liftweb.common.Box

trait AESField[OwnerType <: Record[OwnerType]] extends OwnedField[OwnerType] with HasKey {
  protected def binEncryptSet(plainText:Array[Byte]):OwnerType
  protected def binDecrypt():Box[Array[Byte]]
}

trait TypedAESField[FieldType, OwnerType <: Record[OwnerType]] extends AESField[OwnerType] 
  with TypedConversion[FieldType] {
  def encryptSet(data:FieldType):OwnerType = binEncryptSet(toBytes(data))
  def <<<(data:FieldType) = encryptSet(data)

  def decrypt():Box[FieldType] = binDecrypt.flatMap(pt => fromBytes(pt))
  def >>>() = decrypt()
  def decrypt_!():FieldType = decrypt.open_!
  def >>!() = decrypt_!
}
