package info.cmlubinski.liftencryptedfields

import net.liftweb.common.Box
import net.liftweb.record.{OwnedField, Record}

trait DetAESField[OwnerType <: Record[OwnerType]] extends OwnedField[OwnerType] with HasKey {
  protected def iv:Array[Byte]
  protected def binEncrypt(plainText:Array[Byte]):Array[Byte]
  protected def binEncryptSet(plainText:Array[Byte]):OwnerType
  protected def binDecrypt():Box[Array[Byte]]
}

trait TypedDetAESField[FieldType, OwnerType <: Record[OwnerType]] extends DetAESField[OwnerType] 
  with TypedConversion[FieldType] {
  def encryptSet(data:FieldType):OwnerType = binEncryptSet(toBytes(data))
  def encrypt(data:FieldType):Array[Byte] = binEncrypt(toBytes(data))
  def <<!(data:FieldType) = encryptSet(data)
  def <<?(data:FieldType) = encrypt(data)

  def decrypt():Box[FieldType] = binDecrypt.flatMap(pt => fromBytes(pt))
  def >>>() = decrypt()
  def decrypt_!():FieldType = decrypt.open_!
  def >>!() = decrypt_!
}
