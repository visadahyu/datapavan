---
title: "Politique de confidentialité"
---

Ceci est une traduction. Le [texte anglais](https://datapavan.org/privacy/index.html) est celui qui s’applique.

- **En vigueur :** 2026-11-07
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

## La version 0.1 ne peut pas ouvrir de connexions réseau

Datapavan Basic 0.1 ne demande pas l’autorisation INTERNET : Android lui-même l’empêche donc d’ouvrir des connexions réseau. La compilation échoue si un composant essaie d’ajouter cette autorisation. Comme toute appli, elle peut quand même transmettre des informations à une autre appli quand vous le lui demandez, par exemple quand vous ouvrez un lien.

Ce que fait Android lui-même échappe à Datapavan. Sur les téléphones dotés des services de Google, Play Protect peut donner à Google des informations sur les applis que vous installez depuis n’importe quelle source, Datapavan compris, et peut lui envoyer une appli inconnue pour vérification. Vous pouvez désactiver une partie de cela dans les paramètres de Play Protect, sur le Play Store.

## Autorisations et pourquoi elles sont nécessaires

| Autorisation | Sert à | Depuis |
|---|---|---|
| Voir les applis installées | Lister les applis et leurs autorisations | v0.1 |
| Accès aux données d’utilisation (accordé par vous dans les Paramètres ; facultatif) | Montrer combien de données chaque appli a envoyées et reçues, et quelles applis vous n’avez pas ouvertes depuis longtemps. Datapavan ne lit que des totaux et la date de dernière utilisation de chaque appli, jamais quelle appli vous avez ouverte et quand, et n’en garde rien. Quand vous vérifiez une activité dans une appli, il lit aussi les compteurs de trafic totaux du téléphone, qui ne nécessitent aucune autorisation, pour voir si le décompte d’Android est à jour ; ces chiffres restent en mémoire pendant que la vérification est à l’écran | v0.1 |
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
