// Copyright 2025 Traintime PDA authors.
// SPDX-License-Identifier: MPL-2.0

// FIDO WebAuthn session for IDS.
// Handles FIDO registration (soft credential) and FIDO login.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart' as crypto_lib;
import 'package:device_info_plus/device_info_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/widgets.dart';
import 'package:html/parser.dart' as html_parser;
import 'package:pointycastle/export.dart';
import 'package:watermeter/repository/logger.dart';
import 'package:watermeter/repository/preference.dart' as preference;
import 'package:watermeter/repository/xidian_ids/ids_session.dart';

const _rpId = "ids.xidian.edu.cn";
const _origin = "https://ids.xidian.edu.cn";

class FidoSession extends IDSSession {
  // ---------------------------------------------------------------------------
  // Registration
  // ---------------------------------------------------------------------------

  /// Register a FIDO soft credential.
  ///
  /// Requires recheck (secondary verification) to have been completed beforehand
  /// via IdsRecheck.recheckByPassword(). Saves credential to preferences on success.
  Future<void> register({
    required BuildContext context,
  }) async {
    // 0. Visit personalInfo page to establish session cookies
    await dioNoOfflineCheck.get(
      "$_origin/personalInfo/personCenter/index.html",
    );

    // 0.1. Register browser fingerprint with the server.
    //      The browser's common-header.js generates a fingerprint and sends it
    //      to /authserver/bfp/info, which sets the MULTIFACTOR_BROWSER_FINGERPRINT cookie.
    final fingerprint = crypto_lib.md5
        .convert(utf8.encode("TraintimePDA-${DateTime.now().millisecondsSinceEpoch}"))
        .toString()
        .toUpperCase();
    await dioNoOfflineCheck.get(
      "https://ids.xidian.edu.cn/authserver/bfp/info",
      queryParameters: {"bfp": fingerprint},
    );
    log.info("[FidoSession] Registered fingerprint: $fingerprint");

    // 1. startRegister
    // Read REFERERCE_TOKEN cookie for referertoken header
    final cookies = await cookieJar.loadForRequest(
      Uri.parse("$_origin/personalInfo"),
    );
    final refToken = cookies
        .where((c) => c.name == "REFERERCE_TOKEN")
        .firstOrNull
        ?.value;

    log.info("[FidoSession] Cookies before startRegister: "
        "${cookies.map((c) => '${c.name}=${c.value.substring(0, c.value.length > 20 ? 20 : c.value.length)}...').join(', ')}");

    final registerHeaders = <String, String>{
      "X-Requested-With": "XMLHttpRequest",
      "Origin": _origin,
      "Referer": "$_origin/personalInfo/personCenter/index.html",
    };
    if (refToken != null) {
      registerHeaders["referertoken"] = refToken;
    }

    final startResp = await dioNoOfflineCheck.post(
      "https://ids.xidian.edu.cn/personalInfo/accountSecurity/startRegister",
      data: {"n": _randomN()},
      options: Options(
        contentType: "application/json",
        headers: registerHeaders,
      ),
    );

    log.info("[FidoSession] startRegister response: ${startResp.data}");

    final startData = startResp.data;
    if (startData is! Map || startData["code"].toString() != "0") {
      throw FidoException(
        "startRegister failed: ${startData is Map ? startData["message"] : "response error"}",
      );
    }
    final datas = startData["datas"];
    if (datas is! Map) {
      throw const FidoException("startRegister datas error");
    }
    final request = datas["request"];
    if (request is! Map) {
      throw const FidoException("startRegister request error");
    }
    final requestId = request["requestId"];
    final pkcco = request["publicKeyCredentialCreationOptions"];
    if (pkcco is! Map) {
      throw const FidoException("startRegister publicKeyCredentialCreationOptions error");
    }
    final challenge = pkcco["challenge"];
    final rpInfo = pkcco["rp"];
    final userInfo = pkcco["user"];

    if (challenge == null || challenge.isEmpty) {
      throw const FidoException("challenge not obtained");
    }

    // 2. Generate P-256 key pair
    log.info("[FidoSession] Generating P-256 key pair...");
    final keyResult = _generateKeyPair();

    // 3. Build credential
    final credentialId = _randomBytes(20);
    final credentialIdB64 = _base64UrlEncode(credentialId);

    final attestationObject = _buildAttestationObject(
      rpId: rpInfo["id"] ?? _rpId,
      credentialId: credentialId,
      publicKey: keyResult.publicKey,
    );

    final clientDataJson = utf8.encode(jsonEncode({
      "type": "webauthn.create",
      "challenge": challenge,
      "origin": _origin,
      "crossOrigin": false,
    }));

    // Note: Vue app's responseToObject drops rawId, only type+id+response+clientExtensionResults
    final credential = {
      "type": "public-key",
      "id": credentialIdB64,
      "response": {
        "attestationObject": _base64UrlEncode(attestationObject),
        "clientDataJSON": _base64UrlEncode(clientDataJson),
      },
      "clientExtensionResults": {},
    };

    log.info("[FidoSession] credential: ${jsonEncode(credential)}");

    // 4. finishRegister
    final finishCookies = await cookieJar.loadForRequest(
      Uri.parse("$_origin/personalInfo"),
    );
    final finishRefToken = finishCookies
        .where((c) => c.name == "REFERERCE_TOKEN")
        .firstOrNull
        ?.value;

    final finishHeaders = <String, String>{
      "X-Requested-With": "XMLHttpRequest",
      "Origin": _origin,
      "Referer": "$_origin/personalInfo/personCenter/index.html",
    };
    if (finishRefToken != null) {
      finishHeaders["referertoken"] = finishRefToken;
    }

    // Generate unique device name from device info
    final deviceInfo = DeviceInfoPlugin();
    String deviceName = "Traintime PDA";
    if (Platform.isAndroid) {
      final info = await deviceInfo.androidInfo;
      deviceName = "PDA ${info.model}";
    } else if (Platform.isIOS) {
      final info = await deviceInfo.iosInfo;
      deviceName = "PDA ${info.name}";
    } else if (Platform.isMacOS) {
      final info = await deviceInfo.macOsInfo;
      deviceName = "PDA ${info.computerName}";
    }

    final finishResp = await dioNoOfflineCheck.post(
      "https://ids.xidian.edu.cn/personalInfo/accountSecurity/finishRegister",
      data: {
        "deviceName": deviceName,
        "anonbiometricsd": null,
        "response": jsonEncode({
          "requestId": requestId,
          "credential": credential,
          "sessionToken": null,
        }),
        "n": _randomN(),
      },
      options: Options(
        contentType: "application/json",
        headers: finishHeaders,
      ),
    );

    log.info("[FidoSession] finishRegister response: ${finishResp.data}");

    final finishData = finishResp.data;
    if (finishData is! Map) {
      throw const FidoException("finishRegister response error");
    }
    final code = finishData["code"];
    if (code.toString() != "0") {
      throw FidoException(
        "Registration failed: ${finishData["message"] ?? "unknown error"}",
      );
    }

    final finishDatas = finishData["datas"];
    if (finishDatas is! Map) {
      throw const FidoException("finishRegister datas error");
    }
    final anonbiometricsd = finishDatas["anonbiometricsd"];
    if (anonbiometricsd == null || anonbiometricsd.toString().isEmpty) {
      throw const FidoException("anonbiometricsd not obtained");
    }

    // 5. Save credentials
    await preference.setString(
      preference.Preference.fidoCredentialId,
      credentialIdB64,
    );
    await preference.setString(
      preference.Preference.fidoPrivateKeyPem,
      keyResult.privateKeyPem,
    );
    await preference.setString(
      preference.Preference.fidoUserHandle,
      userInfo["id"] ?? "",
    );
    await preference.setString(
      preference.Preference.fidoAnonbiometricsd,
      anonbiometricsd,
    );
    await preference.setBool(preference.Preference.fidoEnabled, true);

    log.info("[FidoSession] FIDO registration successful.");
  }

  // ---------------------------------------------------------------------------
  // FIDO Login
  // ---------------------------------------------------------------------------

  /// Login via FIDO assertion.
  ///
  /// Returns the redirect location URL on success.
  Future<String> fidoLogin({
    String? target,
    void Function(int, String)? onResponse,
  }) async {
    if (onResponse != null) onResponse(10, "fido_process.prepare");

    // 1. GET login page -> parse execution token
    final loginParams = <String, String>{'type': 'userNameLogin'};
    if (target != null) loginParams['service'] = target;

    final loginPage = await dioNoOfflineCheck.get(
      "https://ids.xidian.edu.cn/authserver/login",
      queryParameters: loginParams,
      options: Options(
        validateStatus: (s) => s != null && s >= 200 && s < 400,
      ),
    );

    // If already logged in, server returns 302 with the target URL
    if (loginPage.statusCode == 301 || loginPage.statusCode == 302) {
      final location = loginPage.headers[HttpHeaders.locationHeader];
      if (location != null && location.isNotEmpty) {
        loginState = IDSLoginState.success;
        if (onResponse != null) onResponse(100, "fido_process.done");
        return location.first;
      }
    }

    final page = html_parser.parse(loginPage.data);
    final executionInput = page.querySelector('input[name="execution"]');
    final execution = executionInput?.attributes['value'] ?? '';

    if (execution.isEmpty) {
      throw const FidoException("Failed to obtain execution token");
    }

    // 2. startAssertion
    if (onResponse != null) onResponse(30, "fido_process.start_assertion");

    final username = preference.getString(preference.Preference.idsAccount);
    final usernameB64 = base64.encode(utf8.encode(username));
    final anonbiometricsd =
        preference.getString(preference.Preference.fidoAnonbiometricsd);

    final assertResp = await dioNoOfflineCheck.post(
      "https://ids.xidian.edu.cn/authserver/startAssertion",
      data: jsonEncode({
        "userId": usernameB64,
        "id": anonbiometricsd,
      }),
      options: Options(
        contentType: "application/json;charset=UTF-8",
        headers: {
          "Accept": "application/json, text/javascript, */*; q=0.01",
          "X-Requested-With": "XMLHttpRequest",
          "Referer": "https://ids.xidian.edu.cn/authserver/login",
        },
      ),
    );

    log.info("[FidoSession] startAssertion response: ${assertResp.data}");

    final assertData = assertResp.data;
    if (assertData is! Map) {
      throw const FidoException("startAssertion response error");
    }
    final result = assertData["result"];
    if (result is! Map) {
      throw const FidoException("startAssertion result error");
    }
    final reqData = result["request"];
    if (reqData is! Map) {
      throw const FidoException("startAssertion request error");
    }
    final requestId = reqData["requestId"];
    final pkro = reqData["publicKeyCredentialRequestOptions"];
    if (pkro is! Map) {
      throw const FidoException("startAssertion publicKeyCredentialRequestOptions error");
    }
    final challenge = pkro["challenge"];

    if (challenge == null || challenge.isEmpty) {
      throw const FidoException("assertion challenge not obtained");
    }

    // 3. Generate signature
    if (onResponse != null) onResponse(50, "fido_process.signing");

    final privateKeyPem =
        preference.getString(preference.Preference.fidoPrivateKeyPem);
    final credentialId =
        preference.getString(preference.Preference.fidoCredentialId);
    final userHandle =
        preference.getString(preference.Preference.fidoUserHandle);

    final assertion = _makeAssertion(
      challenge: challenge,
      credentialId: credentialId,
      privateKeyPem: privateKeyPem,
      userHandle: userHandle,
    );

    // 4. Submit FIDO login form
    if (onResponse != null) onResponse(70, "fido_process.submitting");

    final responseJson = jsonEncode({
      "requestId": requestId,
      "credential": assertion,
      "sessionToken": null,
    });

    final formData = {
      "_eventId": "submit",
      "username": usernameB64,
      "responseJson": responseJson,
      "cllt": "fidoLogin",
      "dllt": "generalLogin",
      "lt": "",
      "execution": execution,
    };

    final loginResp = await dioNoOfflineCheck.post(
      "https://ids.xidian.edu.cn/authserver/login",
      queryParameters: target != null ? {'service': target} : null,
      data: formData,
      options: Options(
        contentType: "application/x-www-form-urlencoded",
        validateStatus: (s) => s != null && s >= 200 && s < 400,
      ),
    );

    log.info("[FidoSession] FIDO login status: ${loginResp.statusCode}");

    if (loginResp.statusCode == 301 || loginResp.statusCode == 302) {
      if (onResponse != null) onResponse(80, "fido_process.done");
      return loginResp.headers[HttpHeaders.locationHeader]![0];
    }

    // Check for error in 200 response
    if (loginResp.statusCode == 200) {
      final errPage = html_parser.parse(loginResp.data);
      final errSpan = errPage.querySelector('span#showErrorTip');
      final errMsg = errSpan?.text ?? "FIDO login failed";
      throw FidoException(errMsg);
    }

    throw FidoException("FIDO login failed, status: ${loginResp.statusCode}");
  }

  // ---------------------------------------------------------------------------
  // WebAuthn Crypto Helpers
  // ---------------------------------------------------------------------------

  _KeyPairResult _generateKeyPair() {
    final secureRandom = FortunaRandom();
    secureRandom.seed(KeyParameter(_randomBytes(32)));

    final domainParams = ECDomainParameters("secp256r1");
    final keyParams = ECKeyGeneratorParameters(domainParams);
    final generator = ECKeyGenerator()
      ..init(ParametersWithRandom(keyParams, secureRandom));

    final keyPair = generator.generateKeyPair();
    final privateKey = keyPair.privateKey;
    final publicKey = keyPair.publicKey;

    // Export private key as PKCS#8 PEM
    final privateKeyPem = _exportPrivateKeyPem(privateKey, publicKey);

    return _KeyPairResult(
      privateKey: privateKey,
      publicKey: publicKey,
      privateKeyPem: privateKeyPem,
    );
  }

  Uint8List _buildAttestationObject({
    required String rpId,
    required Uint8List credentialId,
    required ECPublicKey publicKey,
  }) {
    final rpIdHash = crypto_lib.sha256.convert(utf8.encode(rpId)).bytes;
    const flags = 0x41; // UP + AT
    final signCount = [0, 0, 0, 0];
    final aaguid = List.filled(16, 0);
    final credIdLen = [
      (credentialId.length >> 8) & 0xFF,
      credentialId.length & 0xFF,
    ];

    // COSE EC2 public key
    final x = _bigIntToBytes(publicKey.Q!.x!.toBigInteger()!, 32);
    final y = _bigIntToBytes(publicKey.Q!.y!.toBigInteger()!, 32);
    final coseKey = CborMap({
      CborSmallInt(1): CborSmallInt(2), // kty: EC2
      CborSmallInt(3): CborValue(-7), // alg: ES256
      CborSmallInt(-1): CborSmallInt(1), // crv: P-256
      CborSmallInt(-2): CborBytes(x), // x
      CborSmallInt(-3): CborBytes(y), // y
    });

    final coseKeyBytes = cborEncode(coseKey);
    log.info("[FidoSession] COSE key bytes (${coseKeyBytes.length}): ${coseKeyBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ')}");

    final authData = Uint8List.fromList([
      ...rpIdHash,
      flags,
      ...signCount,
      ...aaguid,
      ...credIdLen,
      ...credentialId,
      ...coseKeyBytes,
    ]);
    log.info("[FidoSession] authData (${authData.length} bytes): ${authData.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ')}");

    final attObj = CborMap({
      CborString("fmt"): CborString("none"),
      CborString("attStmt"): CborMap({}),
      CborString("authData"): CborBytes(authData),
    });

    return Uint8List.fromList(cborEncode(attObj));
  }

  Map<String, dynamic> _makeAssertion({
    required String challenge,
    required String credentialId,
    required String privateKeyPem,
    required String userHandle,
  }) {
    final privateKey = _loadPrivateKeyFromPem(privateKeyPem);

    // clientDataJSON
    final clientData = utf8.encode(jsonEncode({
      "type": "webauthn.get",
      "challenge": challenge,
      "origin": _origin,
      "crossOrigin": false,
    }));

    // authenticatorData
    final rpIdHash = crypto_lib.sha256.convert(utf8.encode(_rpId)).bytes;
    const flags = 0x05; // UP + UV
    final authenticatorData = Uint8List.fromList([
      ...rpIdHash,
      flags,
      0,
      0,
      0,
      0,
    ]);

    // Sign: authenticatorData || SHA256(clientDataJSON)
    final clientDataHash = crypto_lib.sha256.convert(clientData).bytes;
    final signedBytes = Uint8List.fromList([
      ...authenticatorData,
      ...clientDataHash,
    ]);

    final signer = Signer("SHA-256/ECDSA")
      ..init(true, PrivateKeyParameter(privateKey));
    final signature = signer.generateSignature(signedBytes) as ECSignature;
    final derSig = _encodeDerSignature(signature.r, signature.s);

    return {
      "type": "public-key",
      "id": credentialId,
      "response": {
        "authenticatorData": _base64UrlEncode(authenticatorData),
        "clientDataJSON": _base64UrlEncode(clientData),
        "signature": _base64UrlEncode(derSig),
        "userHandle": userHandle,
      },
      "clientExtensionResults": {"appid": false},
    };
  }

  // ---------------------------------------------------------------------------
  // PEM / DER Helpers
  // ---------------------------------------------------------------------------

  String _exportPrivateKeyPem(ECPrivateKey privateKey, ECPublicKey publicKey) {
    final d = _bigIntToBytes(privateKey.d!, 32);

    // PKCS#8 PrivateKeyInfo DER encoding for EC P-256
    final ecPoint = publicKey.Q!;
    final pubX = _bigIntToBytes(ecPoint.x!.toBigInteger()!, 32);
    final pubY = _bigIntToBytes(ecPoint.y!.toBigInteger()!, 32);
    final uncompressedPub = Uint8List.fromList([0x04, ...pubX, ...pubY]);

    final innerSeq = _derSequence([
      _derInteger(BigInt.from(1)),
      _derOctetString(d),
      _derBitString(uncompressedPub, tag: 0xA1),
    ]);

    final algorithmSeq = _derSequence([
      _derOid([1, 2, 840, 10045, 2, 1]),
      _derOid([1, 2, 840, 10045, 3, 1, 7]),
    ]);

    final pkcs8Seq = _derSequence([
      _derInteger(BigInt.zero),
      algorithmSeq,
      _derOctetString(innerSeq),
    ]);

    final b64 = base64.encode(pkcs8Seq);
    final pemLines = RegExp(r'.{1,64}').allMatches(b64).map((m) => m.group(0));
    return "-----BEGIN PRIVATE KEY-----\n${pemLines.join("\n")}\n-----END PRIVATE KEY-----";
  }

  ECPrivateKey _loadPrivateKeyFromPem(String pem) {
    final b64 = pem
        .replaceAll("-----BEGIN PRIVATE KEY-----", "")
        .replaceAll("-----END PRIVATE KEY-----", "")
        .replaceAll(RegExp(r'\s+'), "");
    final der = base64.decode(b64);

    // Extract the private key integer 'd' from PKCS#8 DER.
    final dBytes = _extractPrivateKeyD(der);
    final d = _bytesToBigInt(dBytes);

    final domainParams = ECDomainParameters("secp256r1");
    return ECPrivateKey(d, domainParams);
  }

  Uint8List _extractPrivateKeyD(Uint8List pkcs8Der) {
    // Navigate the DER structure to find the private key octet string.
    // After the outer SEQUENCE, skip: version INT (5 bytes), algorithm SEQ (~18 bytes),
    // then the private key OCTET STRING wraps an inner SEQUENCE with: version INT, OCT(d).
    // We search for the pattern: 0x04, 0x20 (OCTET STRING, 32 bytes) after 0x02, 0x01, 0x00 (INT 1).
    for (int i = 0; i < pkcs8Der.length - 34; i++) {
      // Look for inner SEQUENCE start containing INT 1 then OCTET STRING(32)
      if (pkcs8Der[i] == 0x02 &&
          pkcs8Der[i + 1] == 0x01 &&
          pkcs8Der[i + 2] == 0x01 &&
          pkcs8Der[i + 3] == 0x04 &&
          pkcs8Der[i + 4] == 0x20) {
        return pkcs8Der.sublist(i + 5, i + 5 + 32);
      }
    }
    throw const FidoException("Failed to extract private key from PEM");
  }

  Uint8List _encodeDerSignature(BigInt r, BigInt s) {
    return _derSequence([
      _derIntegerRaw(_bigIntToBytes(r, 32)),
      _derIntegerRaw(_bigIntToBytes(s, 32)),
    ]);
  }

  Uint8List _derSequence(List<Uint8List> items) {
    final content = Uint8List.fromList(items.expand((i) => i).toList());
    return _derTlv(0x30, content);
  }

  Uint8List _derInteger(BigInt value) {
    final bytes = _bigIntToBytes(value, (value.bitLength + 7) ~/ 8 + 1);
    return _derTlv(0x02, bytes);
  }

  Uint8List _derIntegerRaw(Uint8List value) {
    // Add leading zero if high bit is set
    Uint8List adjusted;
    if (value.isNotEmpty && (value[0] & 0x80) != 0) {
      adjusted = Uint8List.fromList([0x00, ...value]);
    } else {
      adjusted = value;
    }
    return _derTlv(0x02, adjusted);
  }

  Uint8List _derOctetString(Uint8List value) {
    return _derTlv(0x04, value);
  }

  Uint8List _derBitString(Uint8List value, {int tag = 0x03}) {
    final content = Uint8List.fromList([0x00, ...value]);
    return _derTlv(tag, content);
  }

  Uint8List _derOid(List<int> components) {
    final bytes = <int>[
      components[0] * 40 + components[1],
      for (int i = 2; i < components.length; i++) ..._encodeOidComponent(components[i]),
    ];
    return _derTlv(0x06, Uint8List.fromList(bytes));
  }

  List<int> _encodeOidComponent(int value) {
    if (value < 0x80) return [value];
    final result = <int>[];
    int v = value;
    result.add(v & 0x7F);
    v >>= 7;
    while (v > 0) {
      result.add((v & 0x7F) | 0x80);
      v >>= 7;
    }
    return result.reversed.toList();
  }

  Uint8List _derTlv(int tag, Uint8List value) {
    final lengthBytes = _derLength(value.length);
    return Uint8List.fromList([tag, ...lengthBytes, ...value]);
  }

  List<int> _derLength(int length) {
    if (length < 0x80) return [length];
    if (length < 0x100) return [0x81, length];
    return [0x82, (length >> 8) & 0xFF, length & 0xFF];
  }

  // ---------------------------------------------------------------------------
  // Utility
  // ---------------------------------------------------------------------------

  Uint8List _randomBytes(int length) {
    return Uint8List.fromList(
      List.generate(length, (_) => Random.secure().nextInt(256)),
    );
  }

  String _randomN() {
    return (DateTime.now().millisecondsSinceEpoch / 1000).toStringAsFixed(17);
  }

  String _base64UrlEncode(List<int> data) {
    return base64Url.encode(data).replaceAll("=", "");
  }

  Uint8List _bigIntToBytes(BigInt value, int length) {
    final hex = value.toRadixString(16).padLeft(length * 2, '0');
    return Uint8List.fromList(List.generate(
      length,
      (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
    ));
  }

  BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
  }
}

class _KeyPairResult {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;
  final String privateKeyPem;

  _KeyPairResult({
    required this.privateKey,
    required this.publicKey,
    required this.privateKeyPem,
  });
}

class FidoException implements Exception {
  final String msg;
  const FidoException(this.msg);
  @override
  String toString() => msg;
}
