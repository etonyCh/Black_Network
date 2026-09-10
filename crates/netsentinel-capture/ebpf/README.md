# netsentinel-capture-ebpf

Le programme eBPF de classification de paquets n'est pas inclus dans ce
scaffold — c'est la partie qui mérite le plus de tests/fuzzing avant d'être
chargée en root, donc à écrire et auditer séparément.

Point de départ recommandé :

```bash
cargo install cargo-generate bpf-linker
cargo generate https://github.com/aya-rs/aya-template
```

Le template génère deux crates :
- `netsentinel-capture-ebpf` (le programme noyau, `no_std`, attaché en XDP
  ou TC sur l'interface réseau)
- le binaire userspace correspondant, à fusionner avec
  `../src/main.rs` de ce dossier (chargement via `Ebpf::load_file`,
  lecture de la ring buffer, pont vers le signal D-Bus `packet_captured`)

Références :
- https://aya-rs.dev/book/ — guide officiel
- crate `network-types` pour les définitions d'en-têtes L2/L3/L4 utilisables
  directement dans le programme eBPF
