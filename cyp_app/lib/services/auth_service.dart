// lib/services/auth_service.dart
import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../config.dart'; // const String apiBase = 'http://localhost:4000';

class AuthResult {
  final bool ok;
  final int status;
  final dynamic data;
  final String? message;
  const AuthResult({required this.ok, required this.status, this.data, this.message});
}

class AuthService {
  AuthService._();
  static final AuthService instance = AuthService._();

  static const _tokenKey = 'auth_token';

  String? _token;
  Map<String, dynamic>? _user;
  String? _lastError;

  String? get token => _token;
  Map<String, dynamic>? get user => _user;
  String? get lastError => _lastError;
  bool get isLoggedIn => (_token != null && _token!.isNotEmpty);

  Future<String?> loadToken() async {
    if (_token != null) return _token;
    final prefs = await SharedPreferences.getInstance();
    _token = prefs.getString(_tokenKey);
    return _token;
  }

  Future<void> _saveToken(String? value) async {
    _token = value;
    final prefs = await SharedPreferences.getInstance();
    if (value == null || value.isEmpty) {
      await prefs.remove(_tokenKey);
    } else {
      await prefs.setString(_tokenKey, value);
    }
  }

  Uri _url(String path) {
    final base = apiBase.endsWith('/') ? apiBase.substring(0, apiBase.length - 1) : apiBase;
    final p = path.startsWith('/') ? path : '/$path';
    return Uri.parse('$base$p');
  }

  Map<String, String> _headers({bool withAuth = false}) {
    final h = <String, String>{'Content-Type': 'application/json'};
    if (withAuth && _token != null && _token!.isNotEmpty) {
      h['Authorization'] = 'Bearer $_token';
    }
    return h;
  }

  Future<AuthResult> _postJson(
    String path, {
    Map<String, dynamic>? body,
    bool withAuth = false,
    int timeoutSeconds = 15,
  }) async {
    try {
      final res = await http
          .post(_url(path), headers: _headers(withAuth: withAuth), body: jsonEncode(body ?? const {}))
          .timeout(Duration(seconds: timeoutSeconds));
      return _toAuthResult(res);
    } on TimeoutException {
      return const AuthResult(ok: false, status: 408, message: 'Zeitüberschreitung – Server nicht erreichbar.');
    } catch (e) {
      return AuthResult(ok: false, status: 500, message: 'Unerwarteter Fehler: $e');
    }
  }

  AuthResult _toAuthResult(http.Response res) {
    dynamic decoded;
    String? message;
    try {
      decoded = res.body.isNotEmpty ? jsonDecode(res.body) : null;
      if (decoded is Map && decoded['message'] is String) {
        message = decoded['message'] as String;
      }
    } catch (_) {}
    final ok = res.statusCode >= 200 && res.statusCode < 300;
    return AuthResult(ok: ok, status: res.statusCode, data: decoded, message: message);
  }

  Future<AuthResult> register(String name, String email, String password) async {
    _lastError = null;
    final result = await _postJson('/api/auth/register', body: {'name': name, 'email': email, 'password': password});
    if (result.ok) {
      final map = (result.data is Map) ? result.data as Map : const {};
      final token = map['token'] as String?;
      final user = map['user'];
      if (token != null) await _saveToken(token);
      if (user is Map) _user = Map<String, dynamic>.from(user);
    } else {
      _lastError = result.message;
    }
    return result;
  }

  Future<AuthResult> login(String email, String password) async {
    _lastError = null;
    final result = await _postJson('/api/auth/login', body: {'email': email, 'password': password});
    if (result.ok) {
      final map = (result.data is Map) ? result.data as Map : const {};
      final token = map['token'] as String?;
      final user = map['user'];
      if (token != null) await _saveToken(token);
      if (user is Map) _user = Map<String, dynamic>.from(user);
    } else {
      _lastError = result.message;
    }
    return result;
  }

  Future<AuthResult> me() async {
    _lastError = null;
    await loadToken();
    if (_token == null || _token!.isEmpty) {
      const res = AuthResult(
        ok: false,
        status: 401,
        message: 'Kein Token vorhanden – bitte einloggen.',
        data: {'message': 'Kein Token vorhanden – bitte einloggen.'},
      );
      _lastError = res.message;
      return res;
    }
    final result = await _postJson('/api/profile/me', withAuth: true);
    if (result.ok) {
      final map = (result.data is Map) ? result.data as Map : const {};
      final user = map['user'];
      if (user is Map) _user = Map<String, dynamic>.from(user);
    } else {
      _lastError = result.message;
    }
    return result;
  }

  Future<void> logout() async {
    _user = null;
    _lastError = null;
    await _saveToken(null);
  }
}