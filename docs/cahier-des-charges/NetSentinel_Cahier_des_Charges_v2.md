# NetSentinel — Cahier des Charges Fonctionnel, Technique & Sécurité (v2.0)
### Application native GNOME/GTK4 pour Ubuntu 24.04 LTS "Noble Numbat"

**Statut :** Révision experte — base v1.0 fournie par le client, enrichie côté architecture, cybersécurité (OWASP Top 10 Web/Desktop + OWASP Top 10 for LLM Applications 2025), tests, CI/CD, packaging et exploitation.
**Public cible de ce document :** équipe de développement humaine **et** agent LLM assistant au développement (Claude Code, etc.). Chaque section majeure contient un bloc `🤖 Instructions pour l'agent LLM` qui précise les livrables attendus et les critères d'acceptation.

---

## 0. Préambule — Cadre légal, éthique et périmètre d'autorisation

NetSentinel est un outil offensif/défensif (scan actif, interception MitM, capture de trafic, extraction de secrets en clair, énumération de répertoires et sous-domaines). Ces capacités sont **strictement réservées à des tests autorisés** sur des périmètres dont l'utilisateur est propriétaire ou pour lesquels il dispose d'une autorisation écrite (règles d'engagement / *Rules of Engagement*).

**Exigences non négociables :**
- **RE-01** — Au premier lancement et à la création de chaque session (module *History*), l'application doit afficher une boîte de dialogue `Adw.AlertDialog` de confirmation d'autorisation, journalisée (horodatage + hash de l'acceptation) dans la base d'audit.
- **RE-02** — Un mode *Périmètre autorisé* doit être associé à chaque session (liste de CIDR/domaines cibles). Toute action active (scan, brute-force, MitM) en dehors de ce périmètre doit être **bloquée par défaut** et nécessiter une confirmation explicite supplémentaire.
- **RE-03** — Le document ne constitue pas un avis juridique. Le cahier des charges ne couvre pas la conformité RGPD/locale complète (à valider avec un juriste), mais impose des principes de minimisation des données et de rétention limitée (cf. §9.4).
- **RE-04** — Le proxy MitM (module D) ne doit intercepter **que le trafic de la machine locale** par défaut (bind `127.0.0.1`). L'écoute sur `0.0.0.0` pour tester d'autres appareils du réseau doit être un opt-in explicite avec avertissement légal affiché.

> **Hypothèses retenues par cette révision** (à valider avec le client, sinon considérées comme acceptées) :
> 1. Distribution hybride **Flatpak (UI sandboxée) + paquet .deb privilégié (helper)** — justifiée en §3 et §12.
> 2. CI/CD sur **GitHub Actions** (adaptable GitLab CI sans changement structurel).
> 3. Chiffrement au repos via **SQLCipher**, secrets via **libsecret/GNOME Keyring**.
> 4. LLM externe = **Gemini API** (mentionné dans le doc source) traité comme *untrusted-by-default* au sens OWASP LLM.
> 5. Toutes les versions de paquets ci-dessous sont celles constatées sur Ubuntu 24.04 LTS **au moment de la rédaction (juillet 2026)**. Le pipeline CI doit systématiquement revalider ces versions via `apt-cache policy` / `pip index versions` avant chaque build — ne jamais les considérer comme figées dans le temps.

---

## 1. Objectifs Généraux & Principes Directeurs

1. **Sécurité par conception** : chaque fonctionnalité active (scan, MitM, brute-force) est *opt-in*, journalisée, et validée par le moteur PDDL avant exécution.
2. **Moindre privilège** : l'interface graphique **ne s'exécute jamais en root**. Seuls des binaires helpers dédiés reçoivent des capabilities Linux ciblées (cf. §3.2).
3. **Intégration native GNOME** : respect strict des GNOME HIG, thèmes clair/sombre, Libadwaita.
4. **Stabilité prioritaire sur la nouveauté** : versions verrouillées (lockfiles), pas de dépendances `latest` en production.
5. **Auditabilité totale** : toute action (humaine ou agent IA) est tracée dans un journal inviolable (chaînage cryptographique, cf. §9.3).
6. **IA sous contrainte** : aucun agent IA (L1 triage, L2 remédiation) n'exécute d'action sans validation PDDL + garde-fous OWASP LLM (§7).

---

## 2. Stack Technologique — Versions Verrouillées (Ubuntu 24.04 LTS)

| Composant | Rôle | Version recommandée (juillet 2026) | Source / Remarque |
|---|---|---|---|
| Ubuntu | OS cible | 24.04.x LTS (noyau HWE conseillé) | Support jusqu'en 2029 (2034 avec ESM) |
| Python | Backend | 3.12 (défaut système Noble) | `python3 --version` |
| GTK | UI toolkit | ≥ 4.14 (base Noble) | `apt-cache policy libgtk-4-1` |
| Libadwaita | Widgets Adw | ≥ 1.5 (baseline GNOME 46) | `apt-cache policy libadwaita-1-0` |
| PyGObject | Bindings Python↔GTK | ≥ 3.48 | via `python3-gi` ou venv + `pygobject` |
| Blueprint | Markup UI déclaratif | ≥ 0.14 | `blueprint-compiler` (universe) ou extension SDK Flatpak GNOME |
| SQLite | Persistance | ≥ 3.45 (défaut Noble), mode **WAL** | envisager **SQLCipher** pour chiffrement at-rest |
| nmap | Scan actif | 7.94SVN (paquet APT Noble officiel) | vérifié via dépôts Ubuntu ; NSE scripts PQC/TLS à tenir à jour séparément |
| Wireshark / tshark | Capture passive | 4.2.2 (paquet APT Noble) | version plus récente (4.4.x) disponible via PPA officiel `ppa:wireshark-dev/stable` — **vérifier la clé de signature avant ajout** |
| arp-scan | Découverte L2 | branche stable 1.10.x (APT) | vérifier `apt-cache policy arp-scan` |
| mitmproxy / mitmdump | Proxy MitM | **Ne pas utiliser le paquet APT** (souvent obsolète) — installer via `pipx`/venv isolé, épingler une version testée en CI (ligne 12.x au moment de la rédaction) | Python ≥ 3.12 requis |
| Docker / Podman | Environnement de test réseau | dernière version stable LTS-équivalente | pour les tests d'intégration (§10) |

**🤖 Instructions pour l'agent LLM (Section 2) :**
- Générer un script `scripts/check_versions.sh` qui interroge `apt-cache policy` et `pip index versions` pour chaque dépendance ci-dessus et échoue (`exit 1`) si une version est strictement inférieure au plancher indiqué.
- Ne jamais coder en dur une version "latest" dans les manifestes Flatpak ou `pyproject.toml` : toujours une version épinglée + plage de compatibilité testée.

---

## 3. Architecture Générale

### 3.1 Vue d'ensemble — séparation UI / privilèges

```
┌─────────────────────────────┐        D-Bus (system bus)        ┌───────────────────────────────┐
│   netsentinel-ui (GTK4)     │ <───── Polkit-gated methods ───> │  netsentinel-helperd (daemon)  │
│   Utilisateur non privilégié│                                    │  Capabilities Linux ciblées    │
│   Flatpak sandbox           │                                    │  (setcap, PAS root complet)    │
└─────────────────────────────┘                                    └───────────────────────────────┘
                                                                              │
                                                        spawn via subprocess (argv[], jamais shell=True)
                                                                              ▼
                                                ┌───────────┬───────────┬───────────┬────────────┐
                                                │  nmap     │  dumpcap  │ arp-scan  │  mitmdump   │
                                                │ (setcap   │ (setcap   │ (setcap   │ (utilisateur│
                                                │ cap_net_  │ cap_net_  │ cap_net_  │  dédié,     │
                                                │ raw)      │ raw,admin)│ raw)      │  sans root) │
                                                └───────────┴───────────┴───────────┴────────────┘
```

**Principe clé (inspiré du modèle éprouvé de Wireshark/dumpcap) :** on ne donne **jamais** de capacités élevées à l'application entière. On isole chaque opération sensible dans un binaire helper minimal, auquel on attribue *uniquement* la capability nécessaire via `setcap`, et on restreint son exécution à un groupe système dédié (`netsentinel`) créé à l'installation du paquet `.deb` privilégié.

- `netsentinel-ui` : processus GTK4/Libadwaita, tourne en utilisateur normal, **idéalement packagé en Flatpak** (sandbox portals, pas d'accès disque/réseau brut par défaut).
- `netsentinel-helperd` : service systemd (`--system`), tourne sous un utilisateur système dédié `netsentinel-helper` (pas root), expose une API D-Bus system bus (`org.netsentinel.Helper1`) protégée par des règles **Polkit** (une action = une permission granulaire : `org.netsentinel.scan.active`, `org.netsentinel.capture.start`, `org.netsentinel.proxy.start`, `org.netsentinel.remediate.execute`).
- Les binaires réseau (`nmap`, `dumpcap` — pas `tshark` directement, cf. §5.C — `arp-scan`) reçoivent leurs capabilities via `setcap cap_net_raw,cap_net_admin+eip` sur le binaire lui-même, restreint au groupe `netsentinel`.
- `mitmdump` tourne dans un utilisateur applicatif distinct sans capability réseau élevée (il n'a besoin que de `bind()` sur un port local > 1024).

### 3.2 Pourquoi pas "toute l'app en root" ni "tout en Flatpak sandboxé strict" ?

- **Anti-pattern à éviter** : lancer `netsentinel-ui` (GTK4 + WebKit potentiel pour les previews HTTP + bindings Python) avec des privilèges root démultiplie la surface d'attaque (CVE GTK/Pango/GLib deviendraient des primitives root).
- **Limite du Flatpak pur** : le sandboxing Flatpak restreint fortement l'accès aux sockets raw nécessaires à `arp-scan`/`nmap -sS`/capture de paquets. C'est un compromis assumé : **le composant privilégié (`netsentinel-helperd` + binaires setcap) est distribué hors sandbox via le paquet `.deb`**, tandis que l'UI reste sandboxée et communique par D-Bus system bus (permission Flatpak `--system-talk-name=org.netsentinel.Helper1`).

### 3.3 Communication inter-processus

- D-Bus system bus exclusivement pour les actions privilégiées, avec authentification Polkit par action (prompt d'authentification système si l'utilisateur n'est pas dans le groupe `netsentinel`, ou autorisation silencieuse si membre du groupe **et** action classée "non destructive").
- Aucune commande shell composée par concaténation de chaînes : tout appel `subprocess` utilise un tableau d'arguments (`argv[]`), jamais `shell=True`, jamais de f-string injectée dans une commande (cf. §6, A03 Injection).

**🤖 Instructions pour l'agent LLM (Section 3) :**
- Livrable : un manifeste Polkit (`org.netsentinel.helper.policy`) définissant une action par capacité sensible, avec `implicit_authorization` distinctes pour `active` (inactive/prompt) vs `auth_admin_keep`.
- Livrable : squelette `netsentinel-helperd` en Python (via `python3-dbus` ou `pydbus`) exposant chaque méthode avec une **validation stricte du schéma d'entrée** (utiliser `pydantic` ou équivalent) avant tout `subprocess.run`.
- Ne jamais générer de code qui exécute une commande via une chaîne interpolée. Toujours `subprocess.run([...], shell=False, timeout=..., check=True)`.

---

## 4. Spécifications Ergonomiques (UI/UX) — Conformité GNOME HIG

*(reprise et enrichissement de la section source)*

- **Mise en page adaptative** : `Adw.NavigationSplitView` (panneau latéral escamotable), responsive dès 360px de large (support tablette/petit écran).
- **Barre d'outils** : `Adw.HeaderBar` + `Adw.ToolbarView` pour séparer contenu scrollable et barres fixes.
- **Retours utilisateur** : `Adw.ToastOverlay` (feedback léger), `Adw.StatusPage` (états vides), `Adw.Banner` (avertissements persistants — ex. "Session hors périmètre autorisé").
- **Thème** : support `Adw.StyleManager` clair/sombre/auto, contrastes conformes WCAG AA minimum (accessibilité).
- **Nouveauté sécurité UI** : tout affichage de secret capturé (credentials en clair, cf. module C) doit être **masqué par défaut** (`••••••••`) avec un bouton "Révéler" explicite — chaque révélation est journalisée comme un événement d'audit (qui, quand, quoi).
- **Kill switch global** : un bouton visible en permanence dans le `Adw.HeaderBar` ("Arrêt d'urgence") stoppe instantanément tout scan actif, capture, proxy ou action d'agent IA en cours.

**🤖 Instructions pour l'agent LLM (Section 4) :**
- Décrire chaque écran en **Blueprint (.blp)**, jamais en XML GtkBuilder brut sauf incompatibilité avérée du compilateur Blueprint.
- Fournir un fichier `style.css` minimal respectant les tokens de couleur Libadwaita (ne pas coder de couleurs en dur — utiliser les variables `@accent_color`, `@warning_color`, `@error_color`).

---

## 5. Modules Fonctionnels (A→H) — avec addendum sécurité par module

### A. Network Map (Cartographie Réseau)
**Fonctionnel :** `Gtk.DrawingArea` (ou `GtkSnapshot`/Graphene pour de meilleures perfs sur grands réseaux), statuts en ligne/hors ligne/vulnérable, panneau de détails par nœud (IP, MAC, type, OS deviné).
**Sécurité :**
- Toute IP/MAC affichée doit être échappée avant rendu (éviter l'injection de balises Pango markup si un service renvoie un nom d'hôte malveillant — *stored XSS-like* dans un contexte desktop).
- La découverte d'hôtes (`arp-scan`, `nmap -sn`) reste passive/légère par défaut ; le scan actif approfondi (module B) nécessite une confirmation distincte.

### B. Fingerprint, CTEM & PQC Audit
**Fonctionnel :** scans Nmap configurables (rapide/normal/agressif/IA profond), audit PQC (détection de suites cryptographiques vulnérables au *Harvest Now, Decrypt Later*, vérification de compatibilité ML-KEM/ML-DSA sur SSH et TLS), boutons CTEM/BAS (test ARP spoofing, port scan, validation de correctifs).
**Sécurité :**
- Le mode "agressif"/"IA profond" doit afficher un avertissement explicite (risque de perturbation de services fragiles/IoT) et être bloqué hors périmètre autorisé (RE-02).
- Limiter le débit de scan (`--max-rate` Nmap, timing template ≤ T3 par défaut) pour éviter un déni de service involontaire sur l'hôte cible.
- Les résultats d'audit PQC doivent être **recoupés avec une base de référence signée** (ex. profils NIST) plutôt qu'une simple heuristique locale — éviter la désinformation (cf. §7, LLM09 si un LLM formule la conclusion).

### C. Traffic Capture (Écoute Réseau)
**Fonctionnel :** capture temps réel via le pattern **dumpcap** (voir §3.1 — jamais `tshark` directement en tant que composant setcap, car sa surface de code est bien plus large que `dumpcap`, qui est conçu spécifiquement pour être privilégié), grille de paquets, filtre BPF, extraction passive de secrets en clair.
**Sécurité :**
- Utiliser `dumpcap -i <iface> -w - | tshark -r -` en pipeline découplé : `dumpcap` (petit, auditable, setcap) écrit les paquets, `tshark`/`pyshark` (dissection riche, plus de code = plus de risque) tourne **sans privilège réseau** sur le flux déjà capturé.
- Valider le filtre BPF saisi par l'utilisateur via la bibliothèque de compilation BPF **avant** de le transmettre au binaire (rejet si erreur de syntaxe, jamais de passage direct non validé à un `subprocess`).
- Les secrets extraits sont chiffrés immédiatement en base (SQLCipher) et masqués en UI (cf. §4).

### D. Web Interceptor Proxy (Proxy MitM & Rejeu)
**Fonctionnel :** proxy `mitmdump` piloté via script d'extension Python, flux de requêtes/réponses, module de rejeu modifiable.
**Sécurité :**
- Bind `127.0.0.1` par défaut (RE-04) ; le certificat CA généré par mitmproxy est stocké avec permissions restrictives (`0600`), jamais committé, et son installation dans le magasin de confiance système nécessite une confirmation explicite avec explication du risque (interception TLS = confiance totale accordée à l'app).
- Le module de rejeu, en modifiant l'URL cible d'une requête, peut devenir un vecteur de **SSRF** si l'utilisateur (ou un agent IA, cf. §7 LLM06) rejoue une requête vers une cible interne non autorisée. Le moteur PDDL doit valider que l'URL rejouée reste dans le périmètre de session (RE-02) avant exécution automatique ; une action manuelle par un humain reste toujours autorisée avec avertissement, pas blocage total (l'utilisateur reste souverain sur ses propres tests).
- Purge automatique de la CA mitmproxy et des clés associées à la fin de la session si l'utilisateur ne demande pas explicitement leur conservation.

### E. Active Enumeration (Énumération Active)
**Fonctionnel :** directory buster (wordlist configurable), audit DNS (A/AAAA/MX/NS/TXT) et bruteforce de sous-domaines.
**Sécurité :**
- Cadencement obligatoire (délai minimal configurable, ex. ≥ 50 ms entre requêtes) pour éviter un déni de service involontaire de la cible — cette temporisation n'est **pas** contournable par un agent IA sans validation PDDL explicite (cf. §7 LLM10, Unbounded Consumption appliqué à la cible et pas seulement à l'API LLM).
- En-tête `User-Agent` identifiant clairement l'outil et un contact (transparence, bonnes pratiques de sécurité offensive responsable).
- Validation stricte de la cible contre le périmètre autorisé de la session (RE-02) avant chaque lancement.

### F. History (Historique des Sessions)
**Fonctionnel :** sessions avec titre/description/cible, résumé (équipements, vulnérabilités, score de risque), session active filtrant l'affichage global.
**Sécurité :**
- Chaque session porte le **périmètre autorisé** (RE-02) et l'horodatage de consentement (RE-01) — ce sont des colonnes obligatoires du schéma, pas optionnelles.
- Politique de rétention configurable (§9.4) appliquée par session.

### G. Reports (Générateur de Rapports)
**Fonctionnel :** rapport consolidé (vulnérabilités, topologie, conclusions), export PDF.
**Sécurité :**
- Toute conclusion générée par un LLM (résumé exécutif IA, par exemple) doit être **clairement étiquetée "Généré par IA — à vérifier"** dans le PDF (cf. §7 LLM09 Misinformation), avec renvoi vers les données brutes correspondantes (CVE ID, sortie Nmap brute, etc.).
- Le PDF ne doit jamais embarquer de secrets en clair non masqués (reprendre la règle de masquage du §4) sans action de "révélation" explicite et journalisée avant export.

### H. Settings (Configuration Générale)
**Fonctionnel :** sélection d'interface réseau, configuration de clé API (Gemini).
**Sécurité :**
- **Aucune clé API en clair sur disque.** Stockage exclusif via `libsecret`/GNOME Keyring (Secret Service D-Bus API). Le fichier de config ne contient qu'une référence logique (`keyring:netsentinel/gemini_api_key`), jamais la valeur.
- Écran de consentement explicite avant toute activation d'un agent IA cloud, avec description claire des données susceptibles d'être envoyées à l'API externe (cf. §7 LLM02).
- Interface réseau sélectionnable limitée aux interfaces physiquement présentes (validation via `NetworkManager`/`netifaces`, pas de saisie libre non validée transmise à un `subprocess`).

**🤖 Instructions pour l'agent LLM (Section 5) :**
- Pour chaque module, produire : (1) le modèle SQLite (migration Alembic ou équivalent léger), (2) le wrapper Python du binaire externe avec validation d'entrée `pydantic` + tests unitaires couvrant les cas d'injection, (3) l'écran Blueprint, (4) au moins un test d'intégration utilisant un conteneur Docker cible (jamais un scan contre une IP publique réelle en CI).
- Ne jamais implémenter un module qui contourne la vérification RE-02 (périmètre de session), même "temporairement pour tester" — lever une exception explicite si le contexte de session est absent.

---

## 6. Modèle de Menaces Applicatif — Mapping OWASP Top 10 (2021, adapté au contexte desktop)

| Risque OWASP | Application à NetSentinel | Contrôle exigé |
|---|---|---|
| **A01 – Broken Access Control** | Actions privilégiées (scan actif, MitM, remédiation L2) accessibles sans vérification | Polkit par action (§3.3), vérification RE-02 systématique côté helper (jamais uniquement côté UI) |
| **A02 – Cryptographic Failures** | Secrets capturés, clé API, base SQLite en clair | SQLCipher (base), libsecret (clés/API), TLS pour tout futur endpoint distant, jamais de crypto maison |
| **A03 – Injection** | Construction de commandes `nmap`/`tshark`/`mitmdump`/`arp-scan`/requêtes SQL/filtres BPF | `subprocess` en mode `argv[]` uniquement, requêtes SQL paramétrées (jamais de f-string SQL), validation regex stricte des IP/domaines/CIDR avant tout appel externe |
| **A04 – Insecure Design** | Fonctions offensives sans garde-fou | Moteur PDDL (§8), Rules of Engagement obligatoires (§0), revue de menace STRIDE en Phase 0 de la roadmap (§14) |
| **A05 – Security Misconfiguration** | Proxy exposé sur toutes les interfaces, debug activé en prod | Bind localhost par défaut, flag `--debug` désactivé en build release, `Adw.StyleManager` sans mode debug exposé à l'utilisateur final |
| **A06 – Vulnerable & Outdated Components** | Dépendances Python/PPA obsolètes (CVE Nmap/Wireshark/mitmproxy) | SBOM (CycloneDX), `pip-audit`/`safety`, Dependabot/Renovate, script `check_versions.sh` (§2) en CI bloquante |
| **A07 – Identification & Authentication Failures** | Accès au service D-Bus helper sans authentification | Polkit obligatoire, pas de fallback "autoriser tout" |
| **A08 – Software & Data Integrity Failures** | Paquets non signés, mise à jour non vérifiée | Signature des paquets `.deb` (GPG) et du Flatpak (via Flathub), vérification de checksum des binaires externes téléchargés (Wireshark PPA, etc.) |
| **A09 – Security Logging & Monitoring Failures** | Journal d'audit modifiable/silencieux | Journal chaîné cryptographiquement (§9.3), export vers `journald`/syslog optionnel pour SIEM externe |
| **A10 – SSRF** | Module de rejeu (D) et énumération (E) pointant vers des cibles internes non prévues | Validation systématique du périmètre de session avant toute requête sortante automatisée (cf. §5.D) |

**🤖 Instructions pour l'agent LLM (Section 6) :**
- Chaque Pull Request touchant à un appel `subprocess`, une requête SQL ou une désérialisation doit inclure dans sa description la ligne du tableau ci-dessus concernée et le test associé.
- Générer une suite de tests "abuse cases" dédiée (`tests/security/test_injection.py`) couvrant au minimum : injection de commande via un nom d'hôte DNS malveillant, injection SQL via un champ "titre de session", payload BPF malformé, chemin traversal dans l'export PDF.

---

## 7. Sécurité des Agents IA — Mapping OWASP Top 10 for LLM Applications (2025)

NetSentinel embarque deux niveaux d'agents IA : **L1 (triage)** qui analyse et catégorise, et **L2 (remédiation)** qui *propose* des actions (isolement d'hôte, patch) — jamais exécutées sans passage par le validateur PDDL (§8) et, pour toute action destructive, confirmation humaine explicite. Le tableau suivant applique la taxonomie **OWASP Top 10 for LLM Applications 2025 (LLM01:2025–LLM10:2025)**.

| # | Risque OWASP LLM | Application à NetSentinel | Contrôle exigé |
|---|---|---|---|
| **LLM01** | Prompt Injection | Le trafic capturé (headers HTTP, noms d'hôtes, payloads) est envoyé à l'IA pour "explication contextuelle" — un attaquant peut injecter des instructions dans ces données | Délimitation stricte des données non fiables dans le prompt (balises explicites type `<DONNEES_NON_FIABLES>`), *system prompt* qui interdit explicitement de traiter tout texte capturé comme une instruction, aucune action déclenchée directement par la sortie du LLM (toujours via PDDL) |
| **LLM02** | Sensitive Information Disclosure | Envoi de credentials capturés ou de données réseau internes à l'API Gemini (cloud, hors du périmètre local) | Redaction/anonymisation automatique (regex + classification) avant tout envoi à une API cloud, consentement explicite par type de donnée (§5.H), option "analyse 100% locale" (modèle léger on-device) pour les environnements sensibles |
| **LLM03** | Supply Chain | SDK IA, prompts tiers, dépendances du connecteur Gemini | Épinglage de version du SDK, vérification de la provenance des prompts/templates (pas de chargement dynamique depuis une source non signée) |
| **LLM04** | Data & Model Poisoning | Base de connaissance CVE/NVD utilisée pour enrichir les réponses IA (si RAG) | Sources signées/officielles uniquement (feed NVD via TLS + vérification), pas d'ingestion de contenu communautaire non modéré dans le contexte du modèle |
| **LLM05** | Improper Output Handling | Une commande de remédiation "suggérée" par le LLM pourrait être rendue directement dans l'UI ou pire, `eval()`/exécutée | **Jamais** d'exécution directe d'une sortie LLM. Toute commande proposée transite par : (1) échappement Pango avant affichage, (2) traduction en but PDDL formel, (3) validation logique, (4) confirmation humaine si action à risque |
| **LLM06** | Excessive Agency | L'agent L2 pourrait obtenir un accès trop large aux helpers privilégiés | Permissions Polkit **dédiées et minimales** pour l'agent IA (distinctes de celles de l'utilisateur humain), liste blanche d'actions autorisées à l'agent, kill switch global (§4) coupant aussi les agents |
| **LLM07** | System Prompt Leakage | Le prompt système (règles PDDL, clé API) pourrait fuiter via une réponse du modèle | Ne jamais placer de secret (clé API, chemin interne) dans le prompt système ; traiter le prompt système comme potentiellement exposable |
| **LLM08** | Vector & Embedding Weaknesses | Si une base vectorielle est utilisée pour la recherche de CVE similaires | Isolation des embeddings par session/utilisateur, validation d'intégrité de l'index, pas d'ingestion de documents non fiables dans l'index partagé |
| **LLM09** | Misinformation | Le LLM peut halluciner une gravité de vulnérabilité ou une conformité PQC erronée | Toute affirmation IA dans un rapport (§5.G) doit être recoupée avec une source faisant autorité (CVE/NVD, sortie brute Nmap) et étiquetée "Généré par IA — à vérifier" |
| **LLM10** | Unbounded Consumption | Appels illimités à l'API Gemini (coût), ou agent qui boucle sur des scans réseau (déni de service local) | Rate limiting et budget max configurable sur l'API cloud (timeout, quota journalier), rate limiting réseau du côté PDDL/helper indépendant de l'IA (cf. §5.E) |

**🤖 Instructions pour l'agent LLM (Section 7) :**
- Implémenter une couche "AI Gateway" interne (module Python `netsentinel.ai_gateway`) qui centralise : redaction (LLM02), garde-fous de prompt (LLM01), validation de sortie (LLM05), rate limiting par token/requête (LLM10). Aucun appel direct à l'API Gemini ne doit contourner cette couche.
- Écrire des tests de type *red-team* automatisés (`tests/security/test_prompt_injection.py`) injectant des payloads classiques (instructions cachées dans un User-Agent HTTP capturé, dans un nom d'hôte DNS, dans un header) et vérifiant qu'aucune action privilégiée n'est déclenchée.

---

## 8. Gouvernance des Agents IA & Validation PDDL (renforcée)

*(reprise et durcissement de la section source "4. Garde-fous Logiques & SOC Agentique")*

### 8.1 Moteur de validation PDDL
- Chaque plan proposé par un agent (L1 ou L2) est traduit en un ensemble de buts **PDDL** (préconditions/effets) avant toute exécution.
- **Règle d'isolement** : blocage si l'IP cible = passerelle par défaut (Gateway IP).
- **Règle de patch** : blocage de mise à niveau à chaud d'un service critique sur la passerelle sans failover validé au préalable.
- **Nouvelles règles ajoutées :**
  - **Règle de périmètre** : blocage si la cible de l'action sort du périmètre autorisé de la session active (RE-02).
  - **Règle de taux** : blocage si le rythme d'actions proposées par l'agent dépasse le seuil configuré (anti-boucle, LLM10).
  - **Règle de réversibilité** : toute action non réversible (ex. modification de configuration réseau persistante) exige une confirmation humaine explicite, même si le plan est validé PDDL.
- Le validateur doit être un module **indépendant et déterministe**, testable unitairement sans dépendance à l'IA elle-même (le PDDL ne fait pas confiance au LLM — il revalide tout, y compris pour une action proposée par un humain via l'UI).

### 8.2 Journalisation d'audit des agents IA
Chaque décision (L1/L2) est consignée **immuablement** dans SQLite avec :
- Horodatage précis (UTC, précision milliseconde).
- Identifiant de l'agent et version du modèle utilisé.
- Commande d'action initiée (texte brut, avant et après validation).
- Entrées fournies et sorties générées (avec application de la redaction LLM02 avant stockage si les entrées contiennent des secrets).
- Statut de validation PDDL (Validé / Bloqué) et règle violée le cas échéant.

**🤖 Instructions pour l'agent LLM (Section 8) :**
- Implémenter le validateur PDDL comme un module pur (aucun effet de bord, entièrement testable) avec au moins 90% de couverture de tests, incluant des cas limites (IP de gateway en IPv6, périmètre CIDR se chevauchant partiellement, etc.).
- Le validateur doit être appelé côté `netsentinel-helperd` (privilégié), **jamais uniquement côté UI** — un client D-Bus malveillant ne doit pas pouvoir contourner la validation en émettant directement une commande sans passer par le contrôle.

### 9.3 Journal d'audit inviolable (chaînage cryptographique)
Pour garantir l'intégrité du journal (§8.2 et §0 RE-01) :
- Chaque entrée de log contient `hash_n = SHA-256(hash_{n-1} || contenu_n)`, formant une chaîne façon *append-only ledger*.
- Un export signé (GPG détaché) doit être proposé pour transmission à un tiers (auditeur, SOC externe).
- Toute tentative de modification rétroactive casse la chaîne et doit déclencher une alerte visible dans l'UI au démarrage suivant (`Adw.Banner` d'avertissement d'intégrité).

---

## 9. Gestion des Secrets, Cryptographie & Protection des Données

### 9.1 Secrets
- Clés API, tokens, mots de passe de service : **exclusivement** via `libsecret` (Secret Service D-Bus API / GNOME Keyring). Aucune valeur en clair dans un fichier de configuration, une variable d'environnement persistée, ou un log.

### 9.2 Chiffrement au repos
- Base SQLite principale : **SQLCipher** (AES-256), clé dérivée d'un secret stocké via libsecret (pas de mot de passe saisi à chaque lancement — UX fluide mais sécurisée par l'intégration Keyring de la session GNOME déverrouillée).
- Certificats CA générés par mitmproxy : permissions `0600`, jamais persistés au-delà de la politique de rétention (§9.4).

### 9.3 Journal d'audit inviolable
→ voir §8.2 (chaînage cryptographique détaillé ci-dessus).

### 9.4 Minimisation & rétention des données
- Politique de rétention configurable par défaut à **30 jours** pour les données de session (paquets capturés, secrets extraits), purge automatique (tâche planifiée `systemd timer`) sauf conservation explicite demandée par l'utilisateur.
- Effacement sécurisé (écrasement) des fichiers temporaires de capture (`dumpcap` écrit en `/run/netsentinel/` — `tmpfs`, jamais sur disque persistant par défaut).

**🤖 Instructions pour l'agent LLM (Section 9) :**
- Ne jamais générer de code qui écrit une clé API, un token ou un mot de passe dans un fichier `.env`, `config.ini` ou une table SQLite non chiffrée. Toute tentative doit être remplacée par un appel `Secret.password_store_sync` (libsecret) ou équivalent `python-secretstorage`/`keyring`.
- Fournir un script `scripts/purge_expired_sessions.py` invocable par un timer systemd, avec tests couvrant la logique de rétention.

---

## 10. Stratégie de Tests

| Type de test | Outils recommandés (versions stables) | Portée |
|---|---|---|
| Lint / typage statique | `ruff` (lint + format), `mypy --strict` | 100% du code Python applicatif |
| Tests unitaires | `pytest`, `pytest-cov` (seuil de couverture ≥ 80%, ≥ 90% sur le validateur PDDL et l'AI Gateway) | Chaque module A-H, helper, validateur |
| SAST | `bandit`, `semgrep` (règles Python + règles custom "no shell=True", "no eval") | CI bloquante sur `high`/`critical` |
| Analyse des dépendances | `pip-audit`, SBOM via `syft`/CycloneDX | CI bloquante sur CVE `critical` |
| Détection de secrets | `gitleaks` ou `detect-secrets` en pre-commit + CI | Historique complet du dépôt |
| Tests d'intégration réseau | Conteneurs Docker/Podman jouant le rôle de cibles (hôtes vulnérables volontairement, type `metasploitable`-like **dans un réseau Docker isolé, jamais exposé**) | Modules A, B, C, D, E |
| Fuzzing | `atheris` (fuzzing Python guidé par couverture) sur les parseurs (BPF, réponses HTTP interceptées, JSON `tshark -T ek`) | Parseurs critiques exposés à des données réseau non fiables |
| Tests "abuse case" / red-team IA | Suite dédiée (§6, §7) — injection de commande, prompt injection, SSRF via module de rejeu | Avant chaque release |
| Tests d'UI | `pytest` + framework de test GTK (ou tests manuels scriptés via `dogtail`/`AT-SPI`) | Écrans critiques (consentement RE-01, masquage de secrets) |
| Tests de charge/robustesse | Scénario "scan sur /16" pour vérifier les limites de rate-limiting et l'absence de fuite mémoire (`memray`) | Modules B, C, E |
| Pentest interne | Revue manuelle avant chaque release majeure, checklist basée sur les tableaux §6 et §7 | Release majeure uniquement |

**🤖 Instructions pour l'agent LLM (Section 10) :**
- Chaque module livré (§5) doit s'accompagner de son dossier `tests/unit/`, `tests/integration/` et, si applicable, `tests/security/`.
- Ne jamais marquer une tâche "terminée" si la couverture de test du module concerné est inférieure au seuil défini ci-dessus — signaler explicitement l'écart plutôt que de le masquer.

---

## 11. CI/CD, SBOM, Signature & Gestion des Dépendances

### 11.1 Pipeline (GitHub Actions — adaptable GitLab CI)
```
1. lint            → ruff + mypy --strict
2. unit-tests      → pytest --cov, seuils bloquants
3. sast            → bandit + semgrep
4. secret-scan     → gitleaks
5. dependency-scan → pip-audit + check_versions.sh (§2)
6. build           → flatpak-builder (UI) + dpkg-buildpackage (helper .deb)
7. sbom            → syft → CycloneDX JSON, archivé en artefact de build
8. sign            → cosign/sigstore (artefacts Flatpak), dpkg-sig/GPG (.deb)
9. integration-tests → docker compose (réseau de test isolé), voir §10
10. publish-beta   → canal beta Flathub + PPA "netsentinel-beta"
11. gate-manuel    → validation humaine avant promotion production
12. publish-stable → Flathub stable + PPA stable
```

### 11.2 Gestion des dépendances
- `pyproject.toml` + lockfile (`uv.lock`/`poetry.lock`), hashes activés (`--generate-hashes` si `pip-compile`).
- Mise à jour automatisée mais **non auto-mergée** via Renovate/Dependabot — revue humaine obligatoire, surtout pour `mitmproxy`, `nmap`-wrapper, tout ce qui touche à la couche réseau.

**🤖 Instructions pour l'agent LLM (Section 11) :**
- Générer les workflows `.github/workflows/ci.yml` et `.github/workflows/release.yml` respectant exactement l'ordre ci-dessus (fail-fast : un échec de `sast` ou `dependency-scan` bloque le build, jamais de `continue-on-error` sur ces étapes).
- Ne jamais désactiver une vérification de sécurité "temporairement" dans un commit sans un ticket de suivi explicite référencé dans le message de commit.

---

## 12. Packaging & Déploiement

### 12.1 Canal principal — Flatpak (UI)
- ID d'application : `org.netsentinel.NetSentinel`, runtime `org.gnome.Platform` (version alignée sur GNOME 46/47 selon la disponibilité au moment du build), soumis à **Flathub** pour la distribution et les mises à jour automatiques.
- Permissions minimales déclarées dans le manifeste : `--share=network` (uniquement pour les appels API cloud opt-in), `--system-talk-name=org.netsentinel.Helper1` (communication avec le helper privilégié), **pas** de `--device=all` ni de `--filesystem=host` non justifié.

### 12.2 Canal secondaire — paquet `.deb` privilégié (helper)
- Paquet `netsentinel-helper` distribué via **PPA Launchpad dédié**, signé GPG.
- Script post-installation (`postinst`) : création du groupe système `netsentinel`, application des `setcap` sur les binaires helpers, installation de la règle Polkit, activation du service `systemd --system netsentinel-helperd.service`.
- Alternative entreprise : image conteneur signée pour déploiement via un outil de gestion de parc (Ansible/Landscape) sur flottes Ubuntu 24.04.

### 12.3 Snap — non retenu comme canal principal
- La confinement stricte de Snap complique l'accès aux sockets raw nécessaires à la capture/scan (comparable à la limite Flatpak, §3.2). Snap "classic" lèverait cette limite mais perd l'essentiel du bénéfice de confinement — **non recommandé**, mentionné ici uniquement pour justifier l'écart avec la demande initiale et éviter une redécouverte coûteuse en cours de projet.

**🤖 Instructions pour l'agent LLM (Section 12) :**
- Livrer le manifeste Flatpak (`org.netsentinel.NetSentinel.yml`) et le squelette `debian/` (control, postinst, systemd unit, polkit policy, udev rules si nécessaire) dans deux répertoires distincts (`packaging/flatpak/`, `packaging/deb-helper/`).
- Documenter explicitement dans le `README.md` généré la raison de l'architecture hybride (renvoyer vers §3.2 de ce document).

---

## 13. Exploitation en Production

- **Logging** : structuré JSON vers `journald` (service systemd), rotation gérée nativement par systemd-journald (`SystemMaxUse=`), niveau configurable (INFO par défaut, DEBUG jamais activé par défaut en build release).
- **Limites de ressources** : `systemd` `MemoryMax=`, `CPUQuota=`, `TasksMax=` sur `netsentinel-helperd.service` pour éviter qu'un scan mal configuré ne monopolise la machine hôte.
- **Notifications système** : `Gio.Notification`/libnotify pour les événements critiques (fin de scan, détection de vulnérabilité haute sévérité, alerte d'intégrité du journal §9.3).
- **Mises à jour** : Flathub (canal utilisateur, automatique) + PPA (canal helper privilégié, mise à jour via `unattended-upgrades` opt-in) — **jamais** de mécanisme de mise à jour "maison" non signé (`curl | bash` proscrit).
- **Télémétrie** : strictement opt-in, anonymisée, écran de consentement clair au premier lancement, aucune donnée de trafic/cible ne quitte la machine dans la télémétrie (uniquement métriques d'usage applicatif agrégées).
- **Rapport de crash** : opt-in, via un mécanisme compatible GNOME (ex. intégration `abrt`/rapport local exportable manuellement), jamais d'envoi automatique de dumps mémoire susceptibles de contenir des secrets captés.

**🤖 Instructions pour l'agent LLM (Section 13) :**
- Fournir les fichiers unit systemd avec les directives de limitation de ressources déjà renseignées (valeurs par défaut raisonnables, ex. `MemoryMax=1G` pour le helper, ajustable en configuration).
- Ne jamais implémenter de télémétrie ou de rapport de crash sans l'écran de consentement explicite correspondant livré dans le même changement.

---

## 14. Feuille de Route d'Implémentation pour l'Agent LLM

> Chaque phase doit être livrée avec son propre commit/PR, ses tests (§10), et une checklist de sortie ("Definition of Done") cochée avant de passer à la phase suivante. **Ne pas paralléliser les phases 0 à 2** : elles posent les fondations de sécurité utilisées par tout le reste.

### Phase 0 — Cadrage & Threat Modeling
- Livrables : document STRIDE succinct par module, gabarit "Rules of Engagement" (RE-01/RE-02), schéma d'architecture (§3) validé.
- DoD : chaque module A-H a au moins une menace identifiée et un contrôle associé documenté.

### Phase 1 — Fondations
- Livrables : scaffolding du repo (`src/`, `packaging/`, `tests/`), squelette CI (§11), schéma SQLite + migrations, module `libsecret` de gestion des secrets, module de logging chaîné (§9.3).
- DoD : pipeline CI vert sur un projet "hello world" GTK4/Adw packagé en Flatpak minimal.

### Phase 2 — Settings + History + consentement
- Livrables : Module H (sélection interface, clé API via Keyring), Module F (sessions + périmètre RE-02), écran de consentement RE-01.
- DoD : impossible de créer une session sans périmètre autorisé renseigné et consentement journalisé.

### Phase 3 — Network Map + Host Discovery
- Livrables : Module A, wrapper `arp-scan`/`nmap -sn` avec validation d'entrée, tests d'injection.
- DoD : découverte fonctionnelle contre un réseau Docker de test ; tentative de scan hors périmètre bloquée et journalisée.

### Phase 4 — Fingerprint / CTEM / PQC Audit
- Livrables : Module B, intégration Nmap avancée, moteur de scoring PQC recoupé avec une source de référence.

### Phase 5 — Traffic Capture
- Livrables : Module C, pipeline `dumpcap`/`tshark` découplé (§5.C), masquage des secrets en UI.

### Phase 6 — Web Interceptor Proxy
- Livrables : Module D, intégration `mitmdump`, garde-fou SSRF sur le rejeu (§5.D, §6 A10).

### Phase 7 — Active Enumeration
- Livrables : Module E, rate limiting, validation de périmètre.

### Phase 8 — Agents IA (L1/L2), PDDL, AI Gateway
- Livrables : validateur PDDL (§8.1), AI Gateway (§7), journal chaîné complet, suite red-team IA.
- DoD : aucune action d'agent ne s'exécute sans passage réussi par le validateur PDDL ; tests red-team IA passent à 100%.

### Phase 9 — Reports
- Livrables : Module G, export PDF avec étiquetage "Généré par IA" (LLM09), masquage de secrets respecté à l'export.

### Phase 10 — Durcissement sécurité global
- Livrables : campagne SAST/DAST/fuzzing complète (§10), pentest interne basé sur les tableaux §6/§7, correctifs.
- DoD : zéro finding `critical`/`high` ouvert sur SAST et dependency-scan.

### Phase 11 — Packaging final & release
- Livrables : manifeste Flatpak finalisé, paquet `.deb` helper finalisé, soumission Flathub + PPA, documentation utilisateur et README technique.
- DoD : installation propre sur une Ubuntu 24.04 LTS fraîche via les deux canaux, kill switch et RE-01/RE-02 vérifiés en conditions réelles.

---

## 15. Annexes

### 15.1 Glossaire
- **PDDL** : Planning Domain Definition Language, langage formel de description de plans/préconditions utilisé ici pour valider les actions d'agents avant exécution.
- **HNDL** : *Harvest Now, Decrypt Later*, menace consistant à intercepter du trafic chiffré aujourd'hui pour le déchiffrer plus tard grâce à l'informatique quantique.
- **CTEM/BAS** : Continuous Threat Exposure Management / Breach and Attack Simulation.
- **SBOM** : Software Bill of Materials, inventaire signé des composants logiciels d'une application.

### 15.2 Checklist de conformité rapide (avant toute release)
- [ ] RE-01/RE-02 appliqués et testés
- [ ] Aucun `shell=True` ni concaténation de commande dans le code
- [ ] Aucun secret en clair sur disque (grep CI `gitleaks` vert)
- [ ] SBOM généré et archivé
- [ ] Journal d'audit chaîné vérifié (script d'intégrité passant)
- [ ] Suite red-team IA (LLM01-LLM10) passante
- [ ] Kill switch testé manuellement
- [ ] Paquets Flatpak + .deb installés et fonctionnels sur Ubuntu 24.04 LTS propre

### 15.3 Références (à consulter par l'agent LLM au besoin)
- OWASP Top 10 (2021) — Web Application Security
- OWASP Top 10 for LLM Applications 2025 (LLM01:2025–LLM10:2025), OWASP GenAI Security Project
- GNOME Human Interface Guidelines
- Documentation Flatpak Portals & Polkit
- Documentation Nmap NSE / PQC scripts, Wireshark `dumpcap` security model, mitmproxy addons API
### codebase Structure
netsentinel/
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── .gitignore
├── .pre-commit-config.yaml
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── scripts/
│   ├── check_versions.sh
│   ├── purge_expired_sessions.py
│   └── setup_dev_env.sh
├── docs/
│   ├── cahier-des-charges/NetSentinel_Cahier_des_Charges_v2.md
│   ├── threat-model/STRIDE-<module>.md   (x8, un par module A-H)
│   ├── architecture/architecture.md
│   └── rules-of-engagement-template.md
├── packaging/
│   ├── flatpak/
│   │   ├── org.netsentinel.NetSentinel.yml
│   │   ├── org.netsentinel.NetSentinel.appdata.xml.in
│   │   └── org.netsentinel.NetSentinel.desktop
│   └── deb-helper/debian/
│       ├── control, postinst, prerm, rules, changelog
│       ├── netsentinel-helperd.service
│       └── org.netsentinel.helper.policy
├── data/
│   ├── org.netsentinel.NetSentinel.gschema.xml
│   └── icons/
├── src/netsentinel/
│   ├── __init__.py
│   ├── main.py                        # point d'entrée UI (GApplication)
│   ├── ui/                            # ⚠️ NON privilégié
│   │   ├── application.py, window.py, dbus_client.py
│   │   ├── widgets/kill_switch.py, consent_dialog.py, secret_reveal.py
│   │   ├── style/style.css
│   │   └── views/
│   │       ├── network_map/           # Module A
│   │       ├── fingerprint_ctem_pqc/  # Module B
│   │       ├── traffic_capture/       # Module C
│   │       ├── web_interceptor/       # Module D
│   │       ├── active_enumeration/    # Module E
│   │       ├── history/               # Module F
│   │       ├── reports/               # Module G
│   │       └── settings/              # Module H
│   │           (chacun: __init__.py, view.py, <vue>.blp)
│   ├── helperd/                       # ⚠️ PRIVILÉGIÉ (setcap)
│   │   ├── main.py, dbus_service.py, polkit.py
│   │   └── wrappers/
│   │       ├── nmap_wrapper.py
│   │       ├── arpscan_wrapper.py
│   │       ├── dumpcap_wrapper.py
│   │       ├── tshark_wrapper.py
│   │       └── mitmdump_wrapper.py
│   ├── core/
│   │   ├── session.py, scope_validator.py, models.py
│   │   ├── db/schema.sql, sqlcipher.py, migrations/
│   │   ├── secrets/keyring_store.py
│   │   └── audit/ledger.py, verify.py    # journal chaîné
│   ├── pddl/
│   │   ├── domain.pddl, validator.py
│   │   └── rules/isolation_rule.py, patch_rule.py, scope_rule.py,
│   │             rate_rule.py, reversibility_rule.py
│   ├── ai/                            # AI Gateway (OWASP LLM Top 10)
│   │   ├── ai_gateway.py, redaction.py, prompt_guard.py
│   │   ├── gemini_client.py
│   │   ├── agent_l1_triage.py, agent_l2_remediation.py
│   ├── reports/pdf_generator.py, templates/
│   └── utils/subprocess_safe.py, network_validation.py
└── tests/
    ├── unit/{ui,helperd,core,pddl,ai}/
    ├── integration/docker/docker-compose.test-network.yml
    ├── security/test_injection.py, test_prompt_injection.py,
    │           test_ssrf_replay.py, test_path_traversal.py
    └── fuzz/fuzz_bpf_filter.py, fuzz_tshark_json.py

---

*Fin du cahier des charges v2.0. Toute question de clarification (ex. choix définitif Flatpak vs .deb seul, moteur RAG pour le module G, périmètre exact de conformité RGPD) doit être tranchée avec le client avant la Phase 0 et consignée dans un addendum daté.*
