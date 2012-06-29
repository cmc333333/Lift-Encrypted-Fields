# Lift Encrypted Fields

Adds Authenticated encryption to Lift Record fields.

## Usage
```scala
//  Skipping meta-record info
class User extends Record[User] {
  val email = new AESStringField(this)
  val first = new OptionalAESStringField(this)
}

val u = User.createRecord.email <<< "someone@example.com"
u.first >>> //  Empty
u.email >>> //  Full("someone@example.com")
val someBytes = u.email.get
someBytes(5) = 102
u.email(someBytes)
u.email >>> //  Failure, invalid authentication
```

## Keymanager
AES keys should be stored in a JCEKS-formated keystore (as would be created by the keytool utility.) Each key is
assumed to have the alias "modelName.fieldName" and using the same password as the keystore.

To generate a key:
```bash
> keytool -genseckey -keyalg AES -keysize 256 \
  -storetype JCEKS -keystore /path/to/keystore.jck \
  -storepass password -alias user.email
```

Keymanager should then be configured with the following in your Lift properties file:
```ini
keymanager.file=/path/to/keystore.jck
keymanager.pass=password
```
