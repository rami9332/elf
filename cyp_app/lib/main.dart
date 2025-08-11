import 'dart:convert';
import 'package:flutter/material.dart';

import 'services/auth_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    const gold = Color(0xFFFFC107); // Amber / Gold
    const black = Color(0xFF0B0B0B);

    final colorScheme = ColorScheme.fromSeed(
      seedColor: gold,
      brightness: Brightness.dark,
      // etwas “satteres” Gold
      primary: gold,
      secondary: const Color(0xFFFFD54F),
      background: black,
      surface: const Color(0xFF121212),
    );

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'CYP Auth Demo',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: colorScheme,
        scaffoldBackgroundColor: colorScheme.background,
        appBarTheme: const AppBarTheme(
          backgroundColor: black,
          elevation: 0,
          centerTitle: true,
          titleTextStyle: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w700,
            fontSize: 18,
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF1A1A1A),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF333333)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF333333)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: BorderSide(color: colorScheme.primary, width: 1.2),
          ),
          labelStyle: const TextStyle(color: Colors.white70),
          hintStyle: const TextStyle(color: Colors.white54),
          contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: gold,
            foregroundColor: Colors.black,
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            textStyle: const TextStyle(fontWeight: FontWeight.w700),
          ),
        ),
        outlinedButtonTheme: OutlinedButtonThemeData(
          style: OutlinedButton.styleFrom(
            side: BorderSide(color: colorScheme.primary),
            foregroundColor: colorScheme.primary,
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            textStyle: const TextStyle(fontWeight: FontWeight.w700),
          ),
        ),
      ),
      home: const _AuthPage(),
    );
  }
}

class _AuthPage extends StatefulWidget {
  const _AuthPage({super.key});
  @override
  State<_AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<_AuthPage> {
  final _nameCtrl = TextEditingController(text: 'Rami');
  final _emailCtrl = TextEditingController(text: 'rami@example.com');
  final _pwdCtrl = TextEditingController(text: '123456');

  String _responseText = '';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    // beim Start evtl. vorhandenes Token laden
    AuthService.instance.loadToken();
  }

  // ----------------- Handlers -----------------

  Future<void> _onRegister() async {
    setState(() {
      _busy = true;
      _responseText = 'Sende Registrierung...';
    });

    final result = await AuthService.instance.register(
      _nameCtrl.text.trim(),
      _emailCtrl.text.trim(),
      _pwdCtrl.text,
    );

    setState(() {
      _busy = false;
      _responseText = _prettyJson({
        'ok': result.ok,
        'status': result.status,
        'error': result.ok ? null : (result.message ?? 'Register fehlgeschlagen'),
        'user': AuthService.instance.user,
        'token': _shortToken(AuthService.instance.token),
      });
    });
  }

  Future<void> _onLogin() async {
    setState(() {
      _busy = true;
      _responseText = 'Login...';
    });

    final result = await AuthService.instance.login(
      _emailCtrl.text.trim(),
      _pwdCtrl.text,
    );

    setState(() {
      _busy = false;
      _responseText = _prettyJson({
        'ok': result.ok,
        'status': result.status,
        'error': result.ok ? null : (result.message ?? 'Login fehlgeschlagen'),
        'user': AuthService.instance.user,
        'token': _shortToken(AuthService.instance.token),
      });
    });
  }

  Future<void> _onMe() async {
    setState(() {
      _busy = true;
      _responseText = 'Lade Profil...';
    });

    final result = await AuthService.instance.me();

    setState(() {
      _busy = false;
      _responseText = _prettyJson({
        'ok': result.ok,
        'status': result.status,
        'error': result.ok ? null : (result.message ?? 'Profil konnte nicht geladen werden'),
        'user': AuthService.instance.user,
        'token': _shortToken(AuthService.instance.token),
      });
    });
  }

  Future<void> _onLogout() async {
    await AuthService.instance.logout();
    setState(() {
      _responseText = _prettyJson({
        'ok': true,
        'status': 200,
        'message': 'Lokal ausgeloggt',
        'user': AuthService.instance.user,
        'token': _shortToken(AuthService.instance.token),
      });
    });
  }

  // ----------------- UI -----------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('CYP Auth Demo'),
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _card(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const _SectionTitle('Account'),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _nameCtrl,
                        decoration: const InputDecoration(
                          labelText: 'Name',
                          prefixIcon: Icon(Icons.person),
                        ),
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _emailCtrl,
                        decoration: const InputDecoration(
                          labelText: 'E-Mail',
                          prefixIcon: Icon(Icons.mail),
                        ),
                        keyboardType: TextInputType.emailAddress,
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _pwdCtrl,
                        decoration: const InputDecoration(
                          labelText: 'Passwort',
                          prefixIcon: Icon(Icons.lock),
                        ),
                        obscureText: true,
                      ),
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 12,
                        runSpacing: 12,
                        children: [
                          ElevatedButton.icon(
                            onPressed: _busy ? null : _onRegister,
                            icon: const Icon(Icons.person_add_alt_1),
                            label: const Text('Registrieren'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _busy ? null : _onLogin,
                            icon: const Icon(Icons.login),
                            label: const Text('Login'),
                          ),
                          OutlinedButton.icon(
                            onPressed: _busy ? null : _onMe,
                            icon: const Icon(Icons.account_circle),
                            label: const Text('Profil /me'),
                          ),
                          TextButton.icon(
                            onPressed: _busy ? null : _onLogout,
                            icon: const Icon(Icons.logout, color: Colors.white70),
                            label: const Text('Logout', style: TextStyle(color: Colors.white70)),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          _InfoChip(
                            icon: Icons.verified_user,
                            label: 'Eingeloggt',
                            value: AuthService.instance.isLoggedIn ? 'Ja' : 'Nein',
                          ),
                          const SizedBox(width: 10),
                          _InfoChip(
                            icon: Icons.vpn_key,
                            label: 'Token',
                            value: _shortToken(AuthService.instance.token) ?? '-',
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
                _card(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const _SectionTitle('Antwort'),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: const Color(0xFF151515),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: const Color(0xFF2B2B2B)),
                        ),
                        child: SelectableText(
                          _responseText.isEmpty ? '—' : _responseText,
                          style: const TextStyle(fontFamily: 'monospace', height: 1.35),
                        ),
                      ),
                    ],
                  ),
                ),
                if (_busy) ...[
                  const SizedBox(height: 16),
                  LinearProgressIndicator(color: cs.primary),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ----------------- Helpers -----------------

  String? _shortToken(String? token) {
    if (token == null || token.isEmpty) return null;
    if (token.length <= 24) return token;
    return '${token.substring(0, 12)}…${token.substring(token.length - 12)}';
  }

  String _prettyJson(Map<String, dynamic> map) {
    try {
      const enc = JsonEncoder.withIndent('  ');
      return enc.convert(map);
    } catch (_) {
      return map.toString();
    }
  }

  Widget _card({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xFF101010),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF2B2B2B)),
      ),
      child: child,
    );
  }
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Text(
      text,
      style: TextStyle(
        fontSize: 16,
        fontWeight: FontWeight.w800,
        color: cs.primary,
        letterSpacing: .4,
      ),
    );
  }
}

class _InfoChip extends StatelessWidget {
  const _InfoChip({
    required this.icon,
    required this.label,
    required this.value,
    super.key,
  });

  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        border: Border.all(color: const Color(0xFF2B2B2B)),
        color: const Color(0xFF141414),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: cs.primary),
          const SizedBox(width: 8),
          Text(
            '$label: ',
            style: const TextStyle(color: Colors.white70),
          ),
          Text(
            value,
            style: const TextStyle(fontWeight: FontWeight.w700),
          ),
        ],
      ),
    );
  }
}