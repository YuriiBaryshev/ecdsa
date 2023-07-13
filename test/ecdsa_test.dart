import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:test/test.dart';

void main() {
  group('ECDSA tests', () {
    ECDSA ecdsa = ECDSA();

    setUp(() {
      // Additional setup goes here.
    });

    test('Secp256k1 is set default', () {
      expect(ecdsa.ellipticCurveFacade.curve, getSecp256k1());
    });
  });
}
