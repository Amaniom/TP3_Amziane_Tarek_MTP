# TP3 — Sécurisation d'un serveur Linux

**Machines :** `srv-core` (192.168.56.101) et `srv-edge` (192.168.56.102), Rocky Linux 9.

Dans le sujet c'était `.10` et `.11`, j'ai mis mes vraies adresses.

## Travail réalisé

Snapshots des deux VM avant de commencer. **Capture 1.**

### Mission 1 — Pare-feu
J'ai réactivé firewalld et mis chaque interface dans sa zone (NAT en `drop`, admin en `work`, bond0 et VLAN en `internal`). Zone par défaut : `drop`.

En `work` il ne reste que SSH, avec un log `SSH-NEW` et une limite de 6/min. J'ai aussi ajouté l'ipset `helios-blacklist`.

Depuis srv-edge le port 80 est passé en `filtered`, 10051 est refusé et la rafale est bien bridée.

**Captures : 2 à 11.**

### Mission 2 — SSH
Groupe `ssh-admins` + compte `sysops` (il n'existait pas sur srv-core). J'ai copié la clé de srv-edge et testé avant de couper le mot de passe.

SSH écoute maintenant sur le port 2242 : clé uniquement, root interdit. J'ai aussi fait les réglages crypto, SELinux et pare-feu. Les 7 tests donnent le résultat attendu.

J'ai perdu l'accès SSH un moment pendant cette mission, j'ai réparé par la console (détails dans le rapport).

**Captures : 12 à 22.**

### Mission 3 — Journaux et blocage
Journal persistant, reboot, puis 2 démarrages dans `--list-boots`. Ensuite les requêtes d'investigation, auditd (12 règles) et le script `helios-watch-auth` avec son timer.

Après l'attaque depuis srv-edge, elle a été bloquée. Je l'ai débloquée ensuite.

**Captures : 23 à 40.**

Vérif finale + suppression du sudo temporaire : **captures 41 et 42.**

## Fichiers joints

- `Captures_TP3.pdf` : les 42 captures
- `captures/` : le PDF des captures
- `configs/` : les fichiers récupérés sur la VM
- `RAPPORT.md` : ce qui est demandé dans le sujet
