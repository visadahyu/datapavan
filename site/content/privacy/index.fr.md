---
title: "Politique de confidentialité"
---

Ceci est une traduction. Le [texte anglais](https://datapavan.org/privacy/) est celui qui s’applique.

- **En vigueur :** 2026-11-07
- **Mise à jour :** 2026-11-18, avec les lignes de Datapavan Advanced pour la 0.2.0, qui n’est pas encore publiée
- **Responsable :** le mainteneur de Datapavan (mehdashti), jusqu’à ce que la fondation Visadahyu soit établie

**Datapavan ne collecte aucune donnée sur vous.**

## Ce que cela signifie en pratique

- **Pas de mesure d’audience, pas de rapports de plantage, pas de télémétrie.** L’appli ne contient aucun SDK tiers qui pourrait envoyer des données.
- **Pas de comptes.** Vous ne vous inscrivez jamais et ne nous donnez jamais rien.
- **Pas de serveurs qui reçoivent des données d’utilisateurs.** L’appli n’en contacte aucun. Le site web du projet, datapavan.org, est statique et ne garde aucun journal d’accès. Il ne garde pas non plus de trace des téléchargements qu’il fournit. Les téléchargements depuis GitHub et les boutiques d’applis sont soumis à leurs propres politiques.
- **Tout reste sur votre téléphone.** Toute l’analyse se fait sur l’appareil. Les données de Datapavan lui-même se trouvent dans le stockage privé de l’appli.
- **Aucune sauvegarde ne quitte le téléphone.** La sauvegarde Android dans le cloud et le transfert d’appareil à appareil sont désactivés pour les données de Datapavan.
- **Désinstaller l’appli supprime les données de Datapavan.**

## Ce que Datapavan garde sur votre téléphone

- **Le journal du plan de correction.** Pour chaque changement que vous faites avec le plan : le nom de paquet de l’appli, l’heure, l’écran ouvert, et ce que l’appli détenait avant et après (ses autorisations sensibles, ses accès spéciaux et l’autorisation VPN, et si elle était activée et installée). Il vous permet d’annuler un changement et de voir si l’un d’eux est revenu. L’écran du journal le supprime en un seul appui.
- **L’examen strict des capteurs :** quel accès avait chaque appli quand vous l’avez examinée.
- **Vos paramètres :** l’apparence et, avant Android 13, la langue que vous avez choisie.
- **Les résultats de la recherche de traceurs,** pour que les applis inchangées ne soient pas analysées à nouveau, et les **paquets de données** que vous avez importés.

Tout cela reste dans le stockage privé de l’appli et n’est jamais sauvegardé ni envoyé. Toute personne qui peut ouvrir Datapavan sur votre téléphone déverrouillé peut le voir, comme elle peut voir le reste de l’appli.

**Datapavan Advanced, à partir de la 0.2.0, garde aussi :**

- **Un journal des connexions, seulement si vous choisissez d’en tenir un.** Vous choisissez : ne rien conserver, 1, 7 ou 30 jours ; tant que vous n’avez pas choisi, il ne garde rien. Chaque entrée contient l’appli, l’endroit où elle s’est connectée (l’adresse, le port et le nom, avec la source d’où Datapavan tient le nom), les octets dans chaque sens, l’heure, et si vous utilisiez l’appli à ce moment-là, si elle tournait avec sa notification, ou ni l’un ni l’autre. Chaque entrée est chiffrée avec une clé propre à son jour, que protège le keystore d’Android ; sur un téléphone doté d’un verrouillage de l’écran, les jours précédents ne peuvent être lus que pendant qu’il est déverrouillé. Les jours au-delà de votre choix sont supprimés avec leurs clés, et un seul appui supprime tout. Pour les applis que vous faites passer par votre outil de contournement, le journal ne garde aucune destination, sauf si vous activez cette option.
- **Le trafic récent de chaque appli, pour la vue « Now »,** en mémoire seulement. Il disparaît quand le pare-feu s’arrête.
- **Les paramètres de votre outil de contournement :** si des applis passent par lui et lesquelles, l’hôte et le port de l’outil, et le mot de passe que Datapavan a créé pour lui ; ce mot de passe est chiffré avec une clé que protège le keystore d’Android.
- **Les applis que vous laissez hors du pare-feu,** qui accèdent alors à Internet sans passer par lui : leurs noms, jusqu’à ce que vous les y remettiez.

## La version 0.1 ne peut pas ouvrir de connexions réseau

Datapavan Basic 0.1 ne demande pas l’autorisation INTERNET : Android lui-même l’empêche donc d’ouvrir des connexions réseau. La compilation échoue si un composant essaie d’ajouter cette autorisation. Comme toute appli, elle peut quand même transmettre des informations à une autre appli quand vous le lui demandez, par exemple quand vous ouvrez un lien.

Ce que fait Android lui-même échappe à Datapavan. Sur les téléphones dotés des services de Google, Play Protect peut donner à Google des informations sur les applis que vous installez depuis n’importe quelle source, Datapavan compris, et peut lui envoyer une appli inconnue pour vérification. Vous pouvez désactiver une partie de cela dans les paramètres de Play Protect, sur le Play Store. Le contrôle matériel de Datapavan peut aussi amener Android à contacter Google : sur les téléphones qui obtiennent leurs clés d’attestation auprès du serveur de provisionnement de Google, un contrôle qui n’en trouve plus aucune en demande d’autres à Android (Android 13 prévient le service de provisionnement, et à partir d’Android 14 c’est le keystore qui le sollicite), et Android les récupère par sa propre connexion. Datapavan n’envoie rien lui-même.

## Ce à quoi Datapavan Advanced se connecte

Datapavan Advanced, à partir de la 0.2.0, transmet le trafic de vos applis là où elles l’envoient, en passant par le pare-feu sur le téléphone ; rien de ce trafic ne nous parvient. De lui-même, il demande au résolveur DNS de votre réseau les noms que les applis recherchent, comme le ferait le téléphone sans Datapavan Advanced, par une connexion chiffrée là où le téléphone en utilisait une. Quand vous faites passer des applis par votre outil de contournement, leurs recherches de noms vont à l’outil, et leurs autres requêtes DNS passent par l’outil jusqu’à Quad9, une fondation suisse qui n’enregistre pas les adresses, si bien que Quad9 voit l’adresse de l’outil, pas la vôtre.

## Autorisations et pourquoi elles sont nécessaires

| Autorisation | Sert à | Depuis |
|---|---|---|
| Voir les applis installées | Lister les applis et leurs autorisations | v0.1 |
| Accès aux données d’utilisation (accordé par vous dans les Paramètres ; facultatif) | Montrer combien de données chaque appli a envoyées et reçues, et quelles applis vous n’avez pas ouvertes depuis longtemps. Pour cela, Datapavan ne lit que des totaux et la date de dernière utilisation de chaque appli, et n’en garde rien ; Datapavan Basic ne lit jamais quelle appli vous avez ouverte et quand. Quand vous vérifiez une activité dans une appli, il lit aussi les compteurs de trafic totaux du téléphone, qui ne nécessitent aucune autorisation, pour voir si le décompte d’Android est à jour ; ces chiffres restent en mémoire pendant que la vérification est à l’écran | v0.1 |
| Accès aux données d’utilisation, dans Datapavan Advanced | Savoir, pour chaque connexion, si vous utilisiez son appli à ce moment-là, si elle tournait avec une notification affichée par Android (musique, navigation), ou ni l’un ni l’autre. Pour cela, Advanced lit aussi l’historique où Android note, depuis le démarrage du téléphone, quelle appli était à l’écran et quand, quelles applis faisaient tourner un service de premier plan, lesquelles vous avez utilisées autrement (par exemple en touchant leur notification), et quand l’écran s’est allumé ou éteint et quand l’écran de verrouillage s’est affiché ; et si chaque appli peut afficher des notifications. Ce qu’il en apprend, il ne le garde qu’à deux endroits : en mémoire pour la vue « Now » et, si vous tenez un journal des connexions, sous la forme de l’état de chaque entrée, pendant les jours que vous avez choisis | Datapavan Advanced, à partir de la 0.2.0 |
| État du réseau | Savoir si un VPN est actif. Elle ne permet aucune connexion | v0.1 |
| Masquer les superpositions des autres applis | À partir d’Android 12 : tant que Datapavan est à l’écran, les autres applis ne peuvent pas s’afficher par-dessus. Elle ne permet aucune connexion | Datapavan Basic à partir de la version qui suit la 0.1.2, et Datapavan Advanced |
| VPN (accordé par vous) | Le pare-feu **local**. Le trafic est filtré sur le téléphone et ne nous est jamais envoyé | Datapavan Advanced, à partir de la 0.2.0 |
| Internet | Faire passer le trafic des autres applis par le pare-feu local. Datapavan Basic ne la demande jamais | Datapavan Advanced, à partir de la 0.2.0 |

## Mises à jour facultatives des listes de traceurs (prévu)

Datapavan lui-même ne fait qu’importer des fichiers de listes signés. Si des téléchargements facultatifs arrivent, ils seront récupérés sur un miroir public, et seulement si vous activez cette option. Comme pour tout téléchargement :

- l’opérateur du miroir voit votre adresse IP et l’heure de la demande ;
- l’opérateur, et toute personne qui observe votre réseau, peut savoir que l’appareil utilise Datapavan.

La demande ne contient rien sur votre téléphone, vos applis ou votre activité. Les mises à jour sont signées, et des listes plus anciennes ne sont jamais acceptées à la place de listes plus récentes. Vous pouvez désactiver les mises à jour et importer des fichiers de listes manuellement. Une fois que des miroirs existeront, cette politique nommera chaque opérateur, et dira ce qu’il enregistre et pendant combien de temps.

## Contact

Questions sur cette politique : ouvrez un ticket sur GitHub. Pour tout ce qui est sensible, utilisez le formulaire de signalement privé indiqué dans [SECURITY.md](https://github.com/visadahyu/datapavan/blob/main/SECURITY.md).
