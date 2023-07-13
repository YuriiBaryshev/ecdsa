import 'package:elliptic_curves_facade/elliptic_curves_facade.dart';
import 'package:elliptic/elliptic.dart';
import 'dart:math';
import 'package:pointycastle/pointycastle.dart' show Digest;

/// ECDSA implementation with secp256k1 and SHA3-256 by default
class ECDSA {
  late EllipticCurveFacade ellipticCurveFacade;
  late BigInt _privateKey;
  late ECPoint publicKey;
  late Digest _hashFunction;

  ECDSA([EllipticCurve? curve, Digest? hashFunction]) {
    curve ??= getSecp256k1() as EllipticCurve;
    ellipticCurveFacade = EllipticCurveFacade(curve);
    generateKeyPair();
    _hashFunction = hashFunction ?? Digest("SHA3-256");
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
