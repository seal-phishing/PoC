import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:android_intent_plus/android_intent.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http;


void main() {
  runApp(const LinkPreviewGuardApp());
}

class LinkPreviewGuardApp extends StatefulWidget {
  const LinkPreviewGuardApp({super.key});

  @override
  State<LinkPreviewGuardApp> createState() => _LinkPreviewGuardAppState();
}

class _LinkPreviewGuardAppState extends State<LinkPreviewGuardApp> {
  static const platform = MethodChannel('link_preview_guard/intent');

  String? currentUrl;
  bool initialized = false;

  @override
  void initState() {
    super.initState();
    _handleInitialLink();

    platform.setMethodCallHandler((call) async {
      if (call.method == 'onNewLink') {
        final newUrl = call.arguments as String?;
        print("[FLUTTER] onNewLink: $newUrl");
        if (newUrl != null) {
          setState(() {
            currentUrl = newUrl;
          });
        }
      }
    });
  }

  Future<void> _handleInitialLink() async {
    try {
      final url = await platform.invokeMethod<String>('getInitialLink');
      setState(() {
        currentUrl = url;
        initialized = true;
      });
    } on PlatformException catch (e) {
      debugPrint("Erreur récupération lien initial : ${e.message}");
      setState(() => initialized = true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Link Preview',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: initialized
          ? HomeScreen(
        url: currentUrl,
        onReset: () => setState(() => currentUrl = null),
      )
          : const Scaffold(body: Center(child: CircularProgressIndicator())),
    );
  }
}

class HomeScreen extends StatefulWidget {
  final String? url;
  final VoidCallback onReset;

  const HomeScreen({super.key, required this.url, required this.onReset});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  WebViewController? _webViewController;
  bool webViewReady = false;
  String verdict = '';
  Color verdictColor = Colors.grey;

  static const availableBrowsers = {
    'Chrome': 'com.android.chrome',
    'Firefox': 'org.mozilla.firefox',
    'Brave': 'com.brave.browser',
    'Edge': 'com.microsoft.emmx',
    'Samsung Internet': 'com.sec.android.app.sbrowser',
  };

  @override
  void didUpdateWidget(HomeScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.url != null && widget.url != oldWidget.url) {
      _analyzeUrl(widget.url!);
      _webViewController?.loadRequest(Uri.parse(widget.url!));
      setState(() => webViewReady = false);
    }
  }

  @override
  void initState() {
    super.initState();
    if (widget.url != null) {
      _webViewController = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.disabled)
        ..setNavigationDelegate(
          NavigationDelegate(
            onPageFinished: (_) => setState(() => webViewReady = true),
          ),
        )
        ..loadRequest(Uri.parse(widget.url!));

      _analyzeUrl(widget.url!);
    }
  }

  Future<void> _analyzeUrl(String url) async {
    final apiUrl = Uri.parse("http://10.0.2.2:8001/check_url"); // émulateur Android

    try {
      final response = await http.post(
        apiUrl,
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({"url": url}),
      );

      if (response.statusCode != 200) {
        throw Exception("Status ${response.statusCode}");
      }

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final apiVerdict = (data['verdict'] as String?) ?? 'unknown';
      final source = (data['source'] as String?) ?? '';
      final proba = (data['proba'] is num) ? (data['proba'] as num).toDouble() : 0.0;

      String text;
      Color color;

      final isExternalApi = source == 'OFCS API' ||
          source == 'Google Safe Browsing' ||
          source == 'URLhaus';

      if (isExternalApi && apiVerdict == 'phishing') {
        text = 'Phishing détecté';
        color = Colors.red;
      } else if (source == 'ML' && (apiVerdict == 'phishing' || proba >= 0.80)) {
        // attention : le modèle peut renvoyer "phishing" à p>=0.8 → on l’affiche comme "Risque élevé"
        text = 'Risque élevé';
        color = Colors.red;
      } else if (apiVerdict == 'suspect') {
        text = 'Risque modéré';
        color = Colors.orange;
      } else if (apiVerdict == 'legitimate' || apiVerdict == 'clean') {
        text = 'Risque faible';
        color = Colors.green;
      } else {
        text = 'Analyse indisponible';
        color = Colors.grey;
      }

      setState(() {
        verdict = text;
        verdictColor = color;
      });

    } catch (e) {
      print("Erreur appel API: $e");
      setState(() {
        verdict = 'Erreur d’analyse';
        verdictColor = Colors.grey;
      });
    }
  }

  // Dé-commentez pour utiliser le PoC sans l'appel API Python
/*  void _analyzeUrl(String url) {
    final suspiciousPatterns = ['login', 'secure', 'account', 'paypal', 'bank'];
    final typosquattingChars = ['0', '1', 'l', 'rn'];

    final isSuspicious = suspiciousPatterns.any((p) => url.contains(p));
    final hasTypos = typosquattingChars.any((c) => url.contains(c));

    setState(() {
      if (isSuspicious && hasTypos) {
        verdict = '🚫 Potentiel phishing';
        verdictColor = Colors.red;
      } else if (isSuspicious || hasTypos) {
        verdict = '⚠️ Lien suspect';
        verdictColor = Colors.orange;
      } else {
        verdict = '✅ Lien légitime';
        verdictColor = Colors.green;
      }
    });
  }*/

  void _selectBrowser() async {
    final selected = await showDialog<String>(
      context: context,
      builder: (context) {
        return SimpleDialog(
          title: Text('Choisir un navigateur'),
          children: availableBrowsers.entries.map((entry) {
            return SimpleDialogOption(
              onPressed: () => Navigator.pop(context, entry.value),
              child: Text(entry.key),
            );
          }).toList(),
        );
      },
    );

    if (selected != null) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('preferred_browser', selected);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Navigateur sélectionné !')),
      );
    }
  }

  void _openInPreferredBrowser() async {
    if (widget.url == null) return;

    final prefs = await SharedPreferences.getInstance();
    final selectedPackage = prefs.getString('preferred_browser');

    if (selectedPackage == null) {
      _selectBrowser();
      return;
    }

    final intent = AndroidIntent(
      action: 'android.intent.action.VIEW',
      data: widget.url!,
      package: selectedPackage,
    );

    try {
      await intent.launch();
    } catch (_) {
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text('Erreur'),
          content: Text('Impossible d’ouvrir avec le navigateur sélectionné. Est-il installé ?'),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: Text('OK'),
            ),
          ],
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final isAnalyzing = widget.url != null;

    return WillPopScope(
      onWillPop: () async {
        if (isAnalyzing) {
          widget.onReset();
          return false;
        }
        return true;
      },
      child: Scaffold(
        appBar: AppBar(title: const Text("Link Preview")),
        body: isAnalyzing ? _buildAnalysisView() : _buildWaitingView(),
      ),
    );
  }

  Widget _buildWaitingView() {
    return const Center(
      child: Text(
        "En attente d’un lien…\nCliquez sur un lien pour afficher son analyse.",
        textAlign: TextAlign.center,
        style: TextStyle(fontSize: 18),
      ),
    );
  }

  Widget _buildAnalysisView() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        children: [
          Text("Lien détecté :", style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          SelectableText(widget.url!, style: const TextStyle(fontSize: 16)),
          const SizedBox(height: 16),
          Text(verdict, style: TextStyle(fontSize: 18, color: verdictColor)),
          const SizedBox(height: 16),
          Expanded(
            child: Container(
              decoration: BoxDecoration(border: Border.all(color: Colors.black26)),
              child: webViewReady && _webViewController != null
                  ? WebViewWidget(controller: _webViewController!)
                  : const Center(child: CircularProgressIndicator()),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            icon: const Icon(Icons.open_in_browser),
            label: const Text("Continuer vers le site"),
            onPressed: _openInPreferredBrowser,
          ),
          const SizedBox(height: 8),
          ElevatedButton.icon(
            icon: const Icon(Icons.settings),
            label: const Text("Choisir le navigateur"),
            onPressed: _selectBrowser,
          ),
        ],
      ),
    );
  }
}
