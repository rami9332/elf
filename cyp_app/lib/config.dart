// lib/config.dart
//
// Zentrale API‑Basis-URL für dein Backend.
// Für Flutter Web (Chrome) auf demselben Rechner: localhost:4000.
// Wenn du später auf einem Android-Emulator testest, nimm 10.0.2.2:4000.
// Für iOS-Simulator bleibt localhost:4000 korrekt.

const String apiBase = 'http://192.168.2.179:4000';

// Optional: wenn du öfter zwischen Targets wechselst, kannst du so umschalten:
//
// import 'package:flutter/foundation.dart' show kIsWeb;
// import 'dart:io' show Platform;
//
// String get apiBase {
//   if (kIsWeb) return 'http://localhost:4000';      // Web (Chrome)
//   if (Platform.isAndroid) return 'http://10.0.2.2:4000'; // Android-Emulator
//   return 'http://localhost:4000';                  // iOS-Simulator / Desktop
// }