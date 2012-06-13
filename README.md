# Lift Encrypted Fields

Adds Authenticated encryption to Lift Record fields.

## Todo: Explain KeyManager

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
