# NetSentinel — workspace Rust

Scaffold d'architecture pour NetSentinel : 4 services D-Bus séparés par
niveau de privilège + client GTK4/Libadwaita, tel que discuté. Ce dépôt est
un **point de départ à compiler, corriger et compléter** — pas un produit
fini. Deux services (`netsentinel-discoverd` et `netsentinel-scand`) ont une
implémentation fonctionnelle de bout en bout ; les deux autres sont des
squelettes documentés (voir plus bas pourquoi).

## Structure

```
netsentinel/
├── Cargo.toml                      # workspace
├── crates/
│   ├── netsentinel-proto/          # types + interfaces D-Bus partagées (source de vérité unique)
│   ├── netsentinel-discover/       # Discover1 — scan ARP actif natif (implémenté)
│   ├── netsentinel-capture/        # Capture1 — capture eBPF via Aya (squelette, cf ebpf/README.md)
│   ├── netsentinel-scan/           # Scan1 — orchestration nmap + Nuclei (implémenté)
│   ├── netsentinel-intercept/      # Intercept1 — MITM/ARP spoofing (squelette NON fonctionnel, volontaire)
│   └── netsentinel-gtk/            # client GTK4/Libadwaita
└── packaging/
    ├── apparmor/                   # 1 profil par démon, capacités minimales
    ├── systemd/                    # 1 unit par démon, durcissement individuel
    └── polkit/                     # policy avec action séparée pour Intercept1
```

## Pourquoi 4 services séparés et pas 1 seul démon ?

Chaque démon ne demande que les capacités Linux strictement nécessaires à
sa fonction (voir les profils AppArmor et les units systemd). Un bug de
parsing dans `netsentinel-scand` (qui lit des sorties nmap/Nuclei, donc des
données semi-fiables) ne peut pas dériver vers un accès `CAP_NET_RAW`,
parce que ce process ne l'a jamais eu — même pas de manière temporaire.

## Build

```bash
cd netsentinel
cargo build --workspace --release
```

Notes :
- Le client GTK nécessite `gtk4` et `libadwaita` (≥ 1.9) installés sur le
  système (`libgtk-4-dev`, `libadwaita-1-dev` sur Ubuntu 24.04).
- `netsentinel-captured` ne compilera pas tel quel : le programme eBPF
  référencé n'existe pas encore, voir
  `crates/netsentinel-capture/ebpf/README.md`.
- `netsentinel-discoverd` nécessite `libpnet` — sur Ubuntu 24.04, `pnet`
  compile directement via cargo sans dépendance système supplémentaire.

## Installation (schéma cible, à adapter en paquet .deb)

```bash
# Binaires
sudo install -Dm755 target/release/netsentinel-discoverd  /usr/libexec/netsentinel-discoverd
sudo install -Dm755 target/release/netsentinel-scand       /usr/libexec/netsentinel-scand
sudo install -Dm755 target/release/netsentinel-captured    /usr/libexec/netsentinel-captured
sudo install -Dm755 target/release/netsentinel-interceptd  /usr/libexec/netsentinel-interceptd
sudo install -Dm755 target/release/netsentinel             /usr/bin/netsentinel

# Utilisateurs système dédiés (un par service, principe du moindre privilège)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netsentinel-discover
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netsentinel-capture
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netsentinel-scan
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netsentinel-intercept
sudo groupadd --system netsentinel

# AppArmor
sudo install -Dm644 packaging/apparmor/* /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.libexec.netsentinel-*

# systemd
sudo install -Dm644 packaging/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netsentinel-discoverd netsentinel-captured netsentinel-scand
# netsentinel-interceptd n'est PAS activé automatiquement (voir plus bas)

# Polkit
sudo install -Dm644 packaging/polkit/org.netsentinel.policy /usr/share/polkit-1/actions/org.netsentinel.policy
```

## Sur le module Intercept1

Il est livré ici **non fonctionnel par choix**, pas par oubli technique.
Avant d'y implémenter la logique d'ARP spoofing et le proxy de
déchiffrement, câblez d'abord (dans cet ordre) :

1. l'écran de consentement explicite côté client GTK,
2. la vérification d'autorisation côté serveur (pas seulement côté UI),
3. le journal d'audit signé/append-only,
4. la coupure automatique par durée limite.

Voir les commentaires en tête de `crates/netsentinel-intercept/src/main.rs`
et la policy Polkit dédiée (`org.netsentinel.intercept.run`, `auth_admin`
sans exception) pour le détail. N'utilisez cette fonctionnalité que sur des
réseaux que vous possédez ou pour lesquels vous avez une autorisation
explicite — les lois sur l'accès non autorisé à des systèmes tiers
s'appliquent que l'outil soit "à but pédagogique" ou non.

## Prochaines étapes suggérées

- [ ] Implémenter le programme eBPF de `netsentinel-capture` (cargo-generate aya-template)
- [ ] Écrire les tests d'intégration D-Bus (zbus fournit un bus de test)
- [ ] `cargo fuzz` sur `parse_arp_reply` et le parsing des sorties nmap/Nuclei
- [ ] Finaliser l'UI des 5 pages GTK (actuellement des placeholders)
- [ ] Paquet `.deb` complet avec scripts de post-install (création users, apparmor_parser, systemctl enable)
