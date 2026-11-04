# TP3 — Rapport

Mes adresses : srv-core = 192.168.56.101, srv-edge = 192.168.56.102, mon PC = 192.168.56.1.

## 1. Interfaces et zones

| Interface | Connexion | Zone | Politique | Pourquoi |
|---|---|---|---|---|
| `enp0s3` (NAT) | `enp0s3` | `drop` | rien n'entre | côté Internet on n'offre rien, les réponses (dnf, NTP) passent quand même |
| `enp0s8` (admin) | `Connexion filaire 1` | `work` | SSH seulement, 6/min + log `SSH-NEW`, 10051 refusé | réseau d'admin, on garde juste l'accès admin |
| `bond0` (métier) | `bond0` | `internal` | SSH + 10051/tcp | admin + supervision Zabbix (TP4) |
| `bond0.42` (VLAN) | `bond0.42` | `internal` | pareil | même réseau de confiance |

La connexion admin ne s'appelait pas `admin` chez moi mais `Connexion filaire 1`. Comme `enp0s8` est en DHCP et que mon SSH passe par là, j'ai utilisé `nmcli device reapply` plutôt que `con up` pour ne pas couper.

enp0s9/enp0s10 (les cartes du bond) sont tombées en `drop`, ça ne change rien puisque le filtrage se fait sur `bond0`. **Captures 3 à 6**

nftables : tout est dans une table `inet firewalld`. La chaîne `filter_IN_work` saute dans des sous-chaînes (log, deny, allow) et finit par un log `filter_IN_work_REJECT` + reject. `iptables -S` ne montre quasi rien. **Capture 7**

Tests depuis srv-edge :
- port 80 `closed` → `filtered` ;
- 10051 refusé (rc=1) ;
- la rafale de 12 : 2 passent, le reste est rejeté.

Les traces sont dans `journalctl -k`. **Captures 2, 8 à 11**

Attention, la limite de 6/min compte aussi mes propres connexions. Je me suis fait rejeter plusieurs fois en enchaînant trop vite.

## 2. crypto-policies et sshd_config

Sur Rocky 9, `sshd_config` commence par `Include sshd_config.d/*.conf`. Les fichiers sont lus par ordre alphabétique et c'est **la première valeur lue qui compte**.

`50-redhat.conf` inclut la politique crypto du système (Ciphers, Kex, MACs...). Donc pour la remplacer il faut un fichier lu avant → `05-helios-crypto.conf`. Et pas dans le bloc `Match` de la fin de `10-helios-hardening.conf`.

En plus j'ai passé la politique système en `DEFAULT:NO-SHA1` (ça enlève SHA-1 pour tout le système).

`sshd -T` ne montre plus que chacha20/aes256, les MAC etm sha2, curve25519/dh-group16, ed25519/rsa-sha2-512. Le test 7 en SHA-1 est refusé. **Captures 18, 20, 21**

Deux trucs que j'ai dû adapter :
- Il y avait un `01-permitrootlogin.conf` (`PermitRootLogin yes`), lu avant le nôtre, donc il annulait le `no`. Je l'ai déplacé dans `/root`. **Capture 16**
- `ListenAddress 192.168.56.101` avec une IP en DHCP : j'ai mis `net.ipv4.ip_nonlocal_bind=1` pour que sshd démarre même si l'IP n'est pas encore là. Après le reboot il écoutait bien sur les deux adresses. **Capture 24**

## 3. Changer le port SSH : les 3 conséquences

1. **SELinux** : sshd ne peut écouter que sur un port `ssh_port_t`, donc `semanage port -a -t ssh_port_t -p tcp 2242`. Sans ça : `Bind to port 2242 failed: Permission denied`. Je l'ai eu en vrai. **Captures 20, 25**
2. **Pare-feu** : le service `ssh` = port 22. Il faut ouvrir 2242 (règle riche en `work`, port en `internal`) et enlever l'ancienne règle. **Capture 19**
3. **Clients** : `ssh -p 2242`, `scp -P 2242`, les scripts et la supervision à changer. Nouvelle entrée `[192.168.56.101]:2242` dans `known_hosts`.

## 4. Les 7 tests (depuis srv-edge)

| Test | Résultat | Dans le journal |
|---|---|---|
| 1. port 22 | échec, rc=1 | — |
| 2. sysops par clé | OK (`sysops ssh-admins`) | `Accepted publickey for sysops` |
| 3. root | refusé, rc=255 | `not allowed because ... AllowGroups` |
| 4. mot de passe | refusé, rc=255 | `Connection closed by authenticating user sysops` |
| 5. nadia | refusé, rc=255 | `not allowed because ... AllowGroups` |
| 6. tunnel 10051 | `administratively prohibited` | sysops pas dans helios-ops |
| 7. KEX SHA-1 | refusé, rc=255 | `no matching key exchange method` |

**Captures 21, 22**

## 5. Requêtes d'investigation

| Requête | Ce que ça montre |
|---|---|
| `journalctl -u sshd.service --since '-2h' -p warning` | les échecs de sshd vers 18h30 : `Bind to port 2242 failed: Permission denied`. C'est mon incident SELinux. **Capture 25** |
| `journalctl _SYSTEMD_UNIT=sshd.service -g 'Invalid user\|Failed\|Accepted'` | les connexions acceptées par clé (admin_trake depuis 192.168.56.1) et la ligne `-- Boot --`, donc le journal a bien survécu au reboot. **Capture 25** |
| `journalctl --facility=authpriv --since today` | ouverture de session puis la commande lancée en sudo par admin_trake. **Capture 25** |
| `journalctl _UID=5101 --since today` | `No entries` : nadia n'a rien fait aujourd'hui (son essai SSH a été refusé avant d'ouvrir une session). **Capture 26** |
| `journalctl -t sudo -o json-pretty` | un sudo en détail : qui (`_UID`, `_AUDIT_LOGINUID`), la commande, le boot. **Capture 26** |
| `journalctl -b -1 -p err` | les erreurs du boot d'avant : les mêmes échecs sshd + `nm_dispatcher` à l'arrêt. **Capture 27** |
| `lastb` / `last -F` | `lastb` : les échecs de nadia du 3/11 (tests faillock du TP2). `last` : les reboots d'aujourd'hui et les sessions admin. **Capture 27** |
| `lslogins -u` | dates de mot de passe, expiration audit-ext le 24/11, dernier échec de nadia. **Capture 27** |

## 6. auditd

12 règles chargées. **Capture 28**

`touch`/`rm` dans `sudoers.d` → événements `sudoers`. `helios-lastlog` lancé par julien → `helios-setgid`. **Capture 29**

`ausearch -k privesc` montre les commandes root lancées par admin_trake. **Capture 30**. `aureport` **capture 31**.

J'ai lancé aussi `aureport --auth --summary` mais je ne l'ai pas capturé : dans la liste des comptes il y avait un truc qui ressemble à un mot de passe (tapé un jour à la place du login).

## 7. Blocage automatique

`helios-watch-auth.sh`, même principe que le script d'archivage du TP1 :
- `set -euo pipefail` ;
- `flock` (code 2 si déjà lancé) ;
- logs avec le tag `helios-watch-auth` ;
- liste blanche 192.168.56.1.

Il regarde les échecs SSH des 10 dernières minutes et bloque une IP au-delà de 5 échecs. Si l'IP est déjà dans l'ipset il ne refait rien (pas de 2e alerte). Les IP bloquées sont aussi notées dans `/var/lib/helios/blocked.txt`. Timer toutes les 2 min.

- Codes retour 0 et 2 testés. **Captures 32, 33**
- 1re attaque : seulement 5 `Invalid user`, la limite 6/min du pare-feu a bloqué le reste avant sshd. Donc pas assez pour dépasser 5. 2e vague une minute après → 10. **Captures 34, 35**
- `BLOCAGE 192.168.56.102 : 10 echecs`, l'IP est dans l'ipset. **Capture 36**
- srv-edge ne passe plus (timeout). **Capture 37**
- À 19h02, toujours plus de 5 échecs dans la fenêtre mais `0 nouvelle adresse` → pas de doublon. Ensuite : timer arrêté, IP retirée, timer relancé 11 min plus tard. **Capture 38**
- srv-edge revient, et le timer est reparti. **Captures 39, 40**

## 8. Problèmes

- **Snapshot** : le snapshot à chaud de srv-core est resté bloqué. Après un arrêt propre VirtualBox l'a annulé, j'ai refait des snapshots VM éteintes (`02b-fin-M1` et `02-fin-TP2`).
- **Horloge** : srv-core avait ~25h de retard. chrony ne corrigeait que petit à petit (`makestep 1.0 3`), je l'ai passé à `makestep 1.0 -1` + `chronyc makestep`. Les captures 10 et 11 sont d'avant (« nov. 03 »).
- **Perte de SSH (mission 2)** : `update-crypto-policies --set` a redémarré sshd. Mon fichier de surcharge était déjà en place, donc sshd a voulu passer sur 2242, mais le port n'était pas encore autorisé (SELinux + pare-feu). sshd ne démarrait plus. J'ai réparé par la console VirtualBox (`semanage`, règles 2242, restart sshd), donc pas de capture de ces commandes, juste le résultat (captures 19-20) et les erreurs dans le journal (25, 27). À retenir : ouvrir le port avant tout ce qui peut redémarrer sshd.
- **Bonus** pas fait (`-e 2` demandait un reboot de plus).

## 9. Critères de réussite

| Critère | OK ? | Capture |
|---|---|---|
| zone par défaut `drop`, interfaces dans la bonne zone | oui | 6, 24, 41 |
| `nc` 22 échoue, `ssh -p 2242 sysops` OK par clé | oui | 21, 39 |
| root et nadia refusés | oui | 21 |
| `passwordauthentication no`, `allowgroups ssh-admins` | oui | 20, 41 |
| 2242 dans `ssh_port_t` | oui | 20, 41 |
| lignes `SSH-NEW` dans `journalctl -k` | oui | 10, 41 |
| au moins 2 boots | oui | 24, 41 |
| ≥ 10 règles auditd + événement `sudoers` | oui (12) | 28, 29, 41 |
| 192.168.56.102 dans l'ipset après l'attaque | oui | 36 |
| timer avec prochaine exécution | oui | 40, 41 |

À la fin j'ai supprimé le sudo sans mot de passe temporaire sur les 2 VM, et les deux répondent toujours en SSH. **Capture 42**
