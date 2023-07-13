ECDSA implementation for Dart

## Features

1. Key pair generation
2. Signing messages
3. Verification of yielded signatures

## Getting started

1. Install Dart SDK and Flutter framework.
2. Install IDE (this was developed using Android studio, but any Dart-supporting will do).
3. Run command flutter test in project's folder in order to see that every thing is alright (all tests passed).


## Usage

```dart
Uint8List message = Uint8List.fromList([0, 1, 2, 3]);
ECDSA ecdsa = ECDSA(getP256());
var signature = ecdsa.sign(message);
//...
print(ecdsa.verify(message, signature)); //true
```
One may refer to [example](./example) folder for more sophisticated use case
