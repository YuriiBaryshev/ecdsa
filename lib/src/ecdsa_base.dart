import 'dart:typed_data';

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

  ///Converts Uint8List to BigInt
  BigInt _uint8ListToBigInt(Uint8List list) {
    BigInt output = BigInt.zero;
    for(int i = 0; i < list.length; i++) {
      output = output << 8;
      output = output + BigInt.from(list[i]);
    }
    return output;
  }

  ///Signing message
  ///Mapping/JSON of the following structure is outputted
  ///```
  ///{
  ///   "r": <something> as BigInt
  ///   "s": <something> as BigInt
  ///}
  ///```
  Map<String, BigInt> sign(Uint8List message) {
    Map<String, BigInt> output = {
      "r": BigInt.zero,
      "s": BigInt.zero,
    };

    Uint8List hashValue = _hashFunction.process(message);
    BigInt e = _uint8ListToBigInt(hashValue);
    BigInt k = _generateSecret();
    BigInt kInv = k.modInverse(ellipticCurveFacade.curve.n);
    ECPoint R = ellipticCurveFacade.mulScalar(ellipticCurveFacade.getG(), k);

    BigInt r = R.x % ellipticCurveFacade.curve.n;
    BigInt s = kInv * (e + (r * k) % ellipticCurveFacade.curve.n)
        % ellipticCurveFacade.curve.n;

    k = BigInt.zero;
    kInv = BigInt.zero;

    if((r == BigInt.zero) || (s == BigInt.zero)) {
      output = sign(message);
    } else {
      output["s"] = s;
      output["r"] = r;
    }
    return output;
  }
}
