import 'package:elliptic_curves_facade/elliptic_curves_facade.dart';
import 'package:elliptic/elliptic.dart';
import 'dart:math';

/// ECDSA implementation
class ECDSA {
  late EllipticCurveFacade ellipticCurveFacade;
  late BigInt _privateKey;

  ECDSA([EllipticCurve? curve]) {
    curve ??= getSecp256k1() as EllipticCurve;
    ellipticCurveFacade = EllipticCurveFacade(curve);
    generatePrivateKey();
  }

  ///Generate private key
  void generatePrivateKey() {
    int length = ellipticCurveFacade.curve.n.bitLength >> 3;
    Random generator = Random.secure();
    _privateKey = BigInt.zero;
    for(int i = 0; i < length; i++) {
      _privateKey = (_privateKey << 8) + BigInt.from(generator.nextInt(256));
    }
    _privateKey = _privateKey % ellipticCurveFacade.curve.n;
  }
}
