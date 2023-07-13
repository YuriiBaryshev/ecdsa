import 'dart:typed_data';

import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:test/test.dart';

void main() {
  group('ECDSA tests', () {
    ECDSA ecdsa = ECDSA();
    Uint8List message = Uint8List.fromList([0, 1, 2, 3 , 42]);
    

    setUp(() {
      // Additional setup goes here.
    });

    test('Secp256k1 is set default', () {
      expect(ecdsa.ellipticCurveFacade.curve, getSecp256k1());
    });

    test('signing is compatible with verification', () {
      for(int i = 0; i < 10; i++) {
        var signature = ecdsa.sign(message);
        expect(ecdsa.verify(message, signature), isTrue);
      }
    });
  });
}
