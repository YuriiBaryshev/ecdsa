import 'dart:typed_data';

import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic_curves_facade/elliptic_curves_facade.dart';

void main() {
  ECDSA ecdsaAlice = ECDSA();
  Uint8List message = Uint8List.fromList(([0x61, 0x62, 0x63])); //a, b, c
  var signature = ecdsaAlice.sign(message);
  ECPoint alicePublicKey = ecdsaAlice.publicKey;
  //sending signature and alicePublicKey
  ECDSA ecdsaBob = ECDSA();
  print('${ecdsaBob.verify(message, signature, alicePublicKey)}'); //true
}
