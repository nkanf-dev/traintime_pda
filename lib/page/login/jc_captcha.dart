// Copyright 2023-2025 BenderBlog Rodriguez and contributors
// Copyright 2025 Traintime PDA authors.
// SPDX-License-Identifier: MIT

// https://juejin.cn/post/7284608063914622995

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:encrypter_plus/encrypter_plus.dart' as encrypt;
import 'package:flutter/material.dart';
import 'package:flutter_i18n/flutter_i18n.dart';
import 'package:image/image.dart' as img;
import 'package:styled_widget/styled_widget.dart';
import 'package:watermeter/repository/logger.dart';

class Lazy<T> {
  final T Function() _initializer;

  Lazy(this._initializer);

  T? _value;

  T get value => _value ??= _initializer();
}

/// 轨迹点模型
class TrackPoint {
  final int a; // x 轴位移
  final int b; // y 轴位移
  final int c; // 时间戳 (毫秒)

  TrackPoint(this.a, this.b, this.c);

  Map<String, dynamic> toJson() => {'a': a, 'b': b, 'c': c};
}

class SliderCaptchaClientProvider {
  final String cookie;
  Dio dio = Dio()..interceptors.add(logDioAdapter);

  static const int blockSize = 16;
  static const int keySize = 16;
  static const String aesChars =
      "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";

  /// 生成指定长度的随机字符串
  static String randomString(int n) {
    final random = Random();
    return List.generate(
      n,
      (index) => aesChars[random.nextInt(aesChars.length)],
    ).join();
  }

  /// 加密逻辑
  static String encryptData(String plainText, Uint8List keyBytes) {
    final ivStr = randomString(blockSize);
    final nonce = randomString(blockSize * 4);
    final plain = nonce + plainText;

    final key = encrypt.Key(keyBytes);
    final iv = encrypt.IV.fromUtf8(ivStr);

    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.cbc),
    );

    // encrypt.AES 默认使用 PKCS7 填充，等同于 Python 的 pad(..., 16)
    final encrypted = encrypter.encrypt(plain, iv: iv);

    return encrypted.base64;
  }

  /// 解密逻辑
  static String decryptData(String cipherText, Uint8List keyBytes) {
    final Uint8List fullCipher = base64.decode(cipherText);

    if (fullCipher.length < blockSize * 4) {
      throw Exception("Cipher text is too short to contain nonce.");
    }

    // 根据 Python 逻辑：IV 是密文的第 48-64 字节 (Block 4)
    // 实际密文从第 64 字节开始
    final ivBytes = fullCipher.sublist(blockSize * 3, blockSize * 4);
    final encryptedPayload = fullCipher.sublist(blockSize * 4);

    final key = encrypt.Key(keyBytes);
    final iv = encrypt.IV(ivBytes);

    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.cbc),
    );

    // 解密并自动去除 PKCS7 填充
    final decrypted = encrypter.decrypt(
      encrypt.Encrypted(encryptedPayload),
      iv: iv,
    );

    return decrypted;
  }

  /// 从图片字节数组末尾提取 AES Key
  static Uint8List extractAesKeyFromImage(Uint8List imageBytes) {
    if (imageBytes.length < keySize) {
      throw Exception("Image is too short to contain AES key.");
    }
    return imageBytes.sublist(imageBytes.length - keySize);
  }

  /// 优化后的轨迹生成函数
  List<TrackPoint> generateTracks(int targetX) {
    List<TrackPoint> tracks = [];
    Random random = Random();

    int currentX = 0;
    int currentY = 0;

    // 1. 起始点 [cite: 89, 90]
    tracks.add(TrackPoint(0, 0, 0));

    // 调整后的参数：更大的步长，更紧凑的时间
    // 参考你提供的样本：位移 32 像素仅用了 9 个点
    while (currentX < targetX) {
      int remaining = targetX - currentX;

      // 增大步长随机区间 (5-9 像素)，这样点数会明显减少
      int stepX = remaining > 20
          ? random.nextInt(5) + 5
          : random.nextInt(3) + 1;

      currentX += stepX;
      if (currentX > targetX) currentX = targetX;

      // 减小垂直抖动频率，使其看起来更平滑 [cite: 120]
      if (random.nextDouble() > 0.7) {
        currentY += random.nextBool() ? 1 : -1;
      }

      // 将时间间隔 c 锁定在 20-25ms 之间，匹配你提供的样本
      int stepTime = 20 + random.nextInt(6);

      tracks.add(TrackPoint(currentX, currentY, stepTime));

      if (currentX == targetX) break;
    }

    // 2. 结束点：最后的停留点 [cite: 106, 107]
    tracks.add(TrackPoint(targetX, currentY, 20 + random.nextInt(10)));

    return tracks;
  }

  SliderCaptchaClientProvider({required this.cookie});

  Uint8List? puzzleData;
  Uint8List? pieceData;
  Lazy<Image>? puzzleImage;
  Lazy<Image>? pieceImage;
  Uint8List? extractedKey;

  final double puzzleWidth = 280;
  final double puzzleHeight = 155;
  final double pieceWidth = 44;
  final double pieceHeight = 155;

  Future<void> updatePuzzle() async {
    var rsp = await dio.get(
      "https://ids.xidian.edu.cn/authserver/common/openSliderCaptcha.htl",
      queryParameters: {'_': DateTime.now().millisecondsSinceEpoch.toString()},
      options: Options(headers: {"Cookie": cookie}),
    );

    String puzzleBase64 = rsp.data["bigImage"];
    String pieceBase64 = rsp.data["smallImage"];
    // double coordinatesY = double.parse(rsp.data["tagWidth"].toString());

    puzzleData = const Base64Decoder().convert(puzzleBase64);
    pieceData = const Base64Decoder().convert(pieceBase64);

    extractedKey = extractAesKeyFromImage(pieceData!);

    puzzleImage = Lazy(
      () => Image.memory(
        puzzleData!,
        width: puzzleWidth,
        height: puzzleHeight,
        fit: BoxFit.fitWidth,
      ),
    );
    pieceImage = Lazy(
      () => Image.memory(
        pieceData!,
        width: pieceWidth,
        height: pieceHeight,
        fit: BoxFit.fitWidth,
      ),
    );
  }

  Future<void> solve(BuildContext? context, {int retryCount = 20}) async {
    for (int i = 0; i < retryCount; i++) {
      await updatePuzzle();
      double? answer = _trySolve(puzzleData!, pieceData!);
      if (answer != null && await verify(answer, extractedKey!)) {
        log.info("Parse captcha $i time(s), success.");
        return;
      }
      log.info("Parse captcha $i time(s), failure.");
    }

    log.info("$retryCount failures, fallback to user input.");
    // fallback
    if (context != null && context.mounted) {
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (context) => CaptchaWidget(provider: this)),
      );
    }
    throw CaptchaSolveFailedException();
  }

  Future<bool> verify(double answer, Uint8List key) async {
    final payload = {
      "canvasLength": 280,
      "moveLength": answer.toInt(),
      "tracks": generateTracks(answer.toInt()).map((e) => e.toJson()).toList(),
    };
    log.info(
      "JC_CAPTCHA: Original ${jsonEncode(payload)} "
      "TO SEND ${encryptData(jsonEncode(payload), key)}",
    );
    dynamic result = await dio.post(
      "https://ids.xidian.edu.cn/authserver/common/verifySliderCaptcha.htl",
      data: encryptData(jsonEncode(payload), key),
      options: Options(
        headers: {
          "Cookie": cookie,
          HttpHeaders.contentTypeHeader:
              "application/x-www-form-urlencoded;charset=utf-8",
          HttpHeaders.accessControlAllowOriginHeader:
              "https://ids.xidian.edu.cn",
        },
      ),
    );
    return result.data["errorCode"] == 1;
  }

  static double? _trySolve(
    Uint8List puzzleData,
    Uint8List pieceData, {
    int border = 24,
  }) {
    img.Image? puzzle = img.decodeImage(puzzleData);
    if (puzzle == null) {
      return null;
    }
    img.Image? piece = img.decodeImage(pieceData);
    if (piece == null) {
      return null;
    }

    var bbox = _findAlphaBoundingBox(piece);
    var xL = bbox[0] + border,
        yT = bbox[1] + border,
        xR = bbox[2] - border,
        yB = bbox[3] - border;

    var widthW = xR - xL, heightW = yB - yT, lenW = widthW * heightW;
    var widthG = puzzle.width - piece.width + widthW - 1;

    var meanT = _calculateMean(piece, xL, yT, widthW, heightW);
    var templateN = _normalizeImage(piece, xL, yT, widthW, heightW, meanT);
    var colsW = [
      for (var x = xL + 1; x < widthG + 1; ++x)
        _calculateSum(puzzle, x, yT, 1, heightW),
    ];
    var colsWL = colsW.iterator, colsWR = colsW.iterator;
    double sumW = 0;
    for (var i = 0; i < widthW; ++i) {
      colsWR.moveNext();
      sumW += colsWR.current;
    }
    double nccMax = 0;
    int xMax = 0;
    for (var x = xL + 1; x < widthG - widthW; x += 2) {
      colsWL.moveNext();
      colsWR.moveNext();
      sumW = sumW - colsWL.current + colsWR.current;
      colsWL.moveNext();
      colsWR.moveNext();
      sumW = sumW - colsWL.current + colsWR.current;
      var ncc = _calculateNCC(
        puzzle,
        x,
        yT,
        widthW,
        heightW,
        templateN,
        sumW / lenW,
      );
      if (ncc > nccMax) {
        nccMax = ncc;
        xMax = x;
      }
    }

    return (xMax - xL - 1);
  }

  static List<int> _findAlphaBoundingBox(img.Image image) {
    var xL = image.width, yT = image.height, xR = 0, yB = 0;
    for (var y = 0; y < image.height; y++) {
      for (var x = 0; x < image.width; x++) {
        if (image.getPixel(x, y).a != 255) continue;
        if (x < xL) xL = x;
        if (y < yT) yT = y;
        if (x > xR) xR = x;
        if (y > yB) yB = y;
      }
    }
    return [xL, yT, xR, yB];
  }

  static double _calculateSum(
    img.Image image,
    int x,
    int y,
    int width,
    int height,
  ) {
    double sum = 0;
    for (var yy = y; yy < y + height; yy++) {
      for (var xx = x; xx < x + width; xx++) {
        sum += image.getPixel(xx, yy).luminance;
      }
    }
    return sum;
  }

  static double _calculateMean(
    img.Image image,
    int x,
    int y,
    int width,
    int height,
  ) {
    return _calculateSum(image, x, y, width, height) / width / height;
  }

  static List<double> _normalizeImage(
    img.Image image,
    int x,
    int y,
    int width,
    int height,
    double mean,
  ) {
    return [
      for (var yy = 0; yy < height; yy++)
        for (var xx = 0; xx < width; xx++)
          image.getPixel(xx + x, yy + y).luminance - mean,
    ];
  }

  static double _calculateNCC(
    img.Image window,
    int x,
    int y,
    int width,
    int height,
    List<double> template,
    double meanW,
  ) {
    double sumWt = 0, sumWw = 0.000001;
    var iT = template.iterator;
    for (var yy = y; yy < y + height; yy++) {
      for (var xx = x; xx < x + width; xx++) {
        iT.moveNext();
        var w = window.getPixel(xx, yy).luminance - meanW;
        sumWt += w * iT.current;
        sumWw += w * w;
      }
    }
    return sumWt / sumWw;
  }
}

class CaptchaWidget extends StatefulWidget {
  static double deviation = 5;

  final SliderCaptchaClientProvider provider;

  const CaptchaWidget({super.key, required this.provider});

  @override
  State<CaptchaWidget> createState() => _CaptchaWidgetState();
}

class _CaptchaWidgetState extends State<CaptchaWidget> {
  late Future<SliderCaptchaClientProvider> provider;

  /// 滑块的当前位置。
  double _sliderValue = 0.0;

  /// 滑到哪里了
  final _offsetValue = 0;

  @override
  void initState() {
    updateProvider();
    super.initState();
  }

  Future<void> updateProvider() async {
    _sliderValue = 0;
    provider = widget.provider.updatePuzzle().then((value) => widget.provider);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(FlutterI18n.translate(context, "login.slider_title")),
      ),
      body: FutureBuilder<SliderCaptchaClientProvider>(
        future: provider,
        builder: (context, snapshot) {
          if (!snapshot.hasData) {
            return const Center(child: CircularProgressIndicator());
          } else {
            return Column(
              //mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // 堆叠三层，背景图、裁剪的拼图
                SizedBox(
                  width: snapshot.data!.puzzleWidth,
                  height: snapshot.data!.puzzleHeight,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      // 背景图层
                      snapshot.data!.puzzleImage!.value,
                      // 拼图层
                      Positioned(
                        left:
                            _sliderValue * snapshot.data!.puzzleWidth -
                            _offsetValue,
                        child: snapshot.data!.pieceImage!.value,
                      ),
                    ],
                  ),
                ),
                SizedBox(
                  width: snapshot.data!.puzzleWidth,
                  child: SliderTheme(
                    data: SliderThemeData(
                      thumbColor: Colors.white, // 滑块颜色为白色
                      activeTrackColor: Colors.green[900], // 激活轨道颜色为深绿色
                      inactiveTrackColor: Colors.green[900], // 非激活轨道颜色为深绿色
                      trackHeight: 10.0, // 轨道高度
                      thumbShape: const RoundSliderThumbShape(
                        enabledThumbRadius: 10.0,
                      ), // 滑块形状为圆形
                    ),
                    child: Slider(
                      value: _sliderValue,
                      onChanged: (value) {
                        setState(() {
                          _sliderValue = value;
                          //print(_sliderValue * snapshot.data!.puzzleWidth);
                        });
                      },
                      onChangeEnd: (value) async {
                        bool result = await snapshot.data!.verify(
                          _sliderValue,
                          snapshot.data!.extractedKey!,
                        );
                        if (context.mounted) {
                          result
                              ? Navigator.of(context).pop()
                              : setState(() {
                                  updateProvider();
                                });
                        }
                      },
                    ),
                  ),
                ),
              ],
            ).center();
          }
        },
      ),
    );
  }
}

class CaptchaSolveFailedException implements Exception {}
