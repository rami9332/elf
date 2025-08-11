import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import 'config.dart';
import 'services/auth_service.dart';

class Dashboard extends StatefulWidget {
  final AuthService auth;
  const Dashboard({super.key, required this.auth});

  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  String _meResponse = '—';

  Future<void> _loadMe() async {
    try {
      final res = await http.get(
        Uri.parse('$apiBase/api/profile/me'),
        headers: {'Authorization': 'Bearer ${widget.auth.token}'},
      );
      setState(() => _meResponse = '${res.statusCode}: ${res.body}');
    } catch (e) {
      setState(() => _meResponse = 'Fehler /me: $e');
    }
  }

  void _logout() {
    Navigator.of(context).pushNamedAndRemoveUntil('/', (r) => false);
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.auth.user;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Dashboard'),
        backgroundColor: Colors.black,
        centerTitle: true,
      ),
      backgroundColor: Colors.black,
      body: Padding(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Willkommen${user != null ? ', ${user['name']}' : ''}! 🎉',
              style: const TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.w700,
                color: Colors.amber,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Token (gekürzt): ${widget.auth.token == null ? '-' : widget.auth.token!.substring(0, 24) + '…'}',
              style: const TextStyle(color: Colors.white70),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _loadMe,
              child: const Text('Profil /me laden'),
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: _logout,
              child: const Text('Logout'),
            ),
            const SizedBox(height: 24),
            const Text('Antwort:', style: TextStyle(color: Colors.amber)),
            const SizedBox(height: 6),
            Expanded(
              child: SingleChildScrollView(
                child: SelectableText(
                  _meResponse,
                  style: const TextStyle(color: Colors.white),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}