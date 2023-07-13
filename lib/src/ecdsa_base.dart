import 'package:elliptic_curves_facade/elliptic_curves_facade.dart';
import 'package:elliptic/elliptic.dart';
import 'dart:math';

/// ECDSA implementation
class ECDSA {
  late EllipticCurveFacade ellipticCurveFacade;
  late BigInt _privateKey;
  late ECPoint publicKey;

  ECDSA([EllipticCurve? curve]) {
    curve ??= getSecp256k1() as EllipticCurve;
    ellipticCurveFacade = EllipticCurveFacade(curve);
    generateKeyPair();
  }

  ///Generate key pair
  void generateKeyPair() {
    _privateKey = _generateSecret();
    publicKey = ellipticCurveFacade.mulScalar(ellipticCurveFacade.getG(), _privateKey);
  }

  ///Generates secret
  BigInt _generateSecret() {
    int length = ellipticCurveFacade.curve.n.bitLength >> 3;
    Random generator = Random.secure();
    BigInt secret = BigInt.zero;
    for(int i = 0; i < length; i++) {
      secret = (secret << 8) + BigInt.from(generator.nextInt(256));
    }
    secret = secret % ellipticCurveFacade.curve.n;
    if(secret == BigInt.zero) {
      secret = _generateSecret();
    }
    return secret;
  }
}
