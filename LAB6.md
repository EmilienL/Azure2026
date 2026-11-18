# LAB 6 - Reconnaissance, élévation de privilèges et persistance sur AWS
Dans le LAB 3, l'attaquant a cherché `akia` sur SharePoint, puis a téléchargé le fichier **AWS_workloads_admin_access_credentials.txt**. Interrogé, l'IT confirme que ce fichier contenait une *access key* du compte **Workloads** (455764526305) :
```bash
AccessKeyId : AKIAWUHNOYTQ4QWAELFI
```
La clé n'a pas été révoquée. Le **17/11**, deux jours après l'attaque sur Azure, il faut déterminer si elle a été utilisée.

Les logs **CloudTrail** des 3 comptes AWS sont centralisés dans la table **AWSCloudTrail** de Sentinel (LAB 5).

> Toutes les heures de ce lab sont en **UTC** (heure de Paris = UTC+1).

### Utilisation de la clé volée
Les clés AWS long terme commencent par `AKIA`, les clés temporaires (sessions) par `ASIA`. Chaque appel signé avec une clé la mentionne dans le champ **UserIdentityAccessKeyId** :
```KQL
AWSCloudTrail
| where TimeGenerated > datetime("2026-11-17")
| where UserIdentityAccessKeyId == "AKIAWUHNOYTQ4QWAELFI"
```

+ La clé a-t-elle été utilisée ? À quel utilisateur IAM appartient-elle ?
+ Depuis quelle IP ? La connaissez-vous ?

<details>
<summary>Réponse</summary>

+ Oui : **231 appels** entre 14:12 et 15:11, par l'utilisateur IAM **labs-privesc-user**.
+ Tous depuis **2.25.8.248**, la même IP que l'exfiltration SSH du LAB 4 : c'est bien notre attaquant.
</details>

Regardez les premiers appels :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 02:00:00 PM") .. datetime("2026-11-17 02:30:00 PM"))
| where UserIdentityAccessKeyId == "AKIAWUHNOYTQ4QWAELFI"
| project TimeGenerated, EventName, ErrorCode, UserIdentityArn, SourceIpAddress, UserAgent
| sort by TimeGenerated desc
```

Quel est le **premier** appel ? Avec quel outil ? Pourquoi un attaquant commence-t-il par cet appel ?

<details>
<summary>Réponse</summary>

+ 14:12:25 : **GetCallerIdentity**.
+ Avec **aws-cli/2.31.35** sous Linux.

`GetCallerIdentity` est le « whoami » d'AWS : il ne demande **aucune permission**, réussit toujours et renvoie le compte et l'identité de la clé. C'est le premier réflexe d'un attaquant qui vient de trouver une clé : **vérifier qu'elle est valide** et savoir à qui elle appartient. Viennent ensuite `ListUsers` et `ListBuckets` (14:26), tous deux en **AccessDenied**.
</details>

### Reconnaissance automatisée
Regardez avec quels outils *labs-privesc-user* a travaillé :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 02:00:00 PM") .. datetime("2026-11-17 03:15:00 PM"))
| where UserIdentityArn endswith "labs-privesc-user"
| extend Outil = extract(@"^\[?([^/ ]+)", 1, UserAgent) //Premier mot du user-agent
| summarize Appels = count(), Debut = min(TimeGenerated), Fin = max(TimeGenerated), Exemple = take_any(UserAgent) by Outil
| sort by Debut desc
```

Quel outil reconnaissez-vous ?

<details>
<summary>Réponse</summary>

**ScoutSuite** (`Scout-Suite/5.14.0`), de 14:53 à 14:57. C'est un outil open source d'audit de configuration cloud. Il est utilisé par les auditeurs et par les attaquants pour **cartographier** un compte en une seule commande. Il s'annonce en clair dans le *user-agent*.
</details>

Détaillez son passage :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 02:50:00 PM") .. datetime("2026-11-17 03:00:00 PM"))
| where UserAgent has "Scout-Suite"
| summarize Appels = count(), Succes = countif(isempty(ErrorCode)), Echecs = countif(isnotempty(ErrorCode)), Regions = dcount(AWSRegion), Actions = make_set(EventName) by EventSource
| sort by Appels desc
```

+ Combien de services ont été énumérés ?
+ Combien d'appels au total, combien d'échecs et de succès ?
+ Qu'est-ce qui a réussi ?

<details>
<summary>Réponse</summary>

+ **5 services** apparaissent : EC2, STS, IAM, S3 et CloudFront, sur **13 régions**.
+ **193 appels** : **129 échecs** (`AccessDenied`, `Client.UnauthorizedOperation`) et **64 succès**.
+ Les succès sont **62 `GetCallerIdentity`** (toujours autorisé) et **2 `ListPolicies`**. Tout le reste est refusé, dont 30 `GetPolicyVersion` : ScoutSuite a tenté de lire le contenu des policies.

La clé volée n'a presque aucun droit de lecture. L'attaquant n'a donc obtenu de ScoutSuite qu'une seule information utile : il peut lister les policies.
</details>

### Reconnaissance IAM
Après ScoutSuite, l'attaquant change d'outil. Regardez ses appels juste avant 15:03 :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 02:57:30 PM") .. datetime("2026-11-17 03:02:30 PM"))
| where UserIdentityArn endswith "labs-privesc-user"
| project TimeGenerated, EventName, ErrorCode, SourceIpAddress, UserAgent
| sort by TimeGenerated desc
```

Que cherche-t-il à savoir ? Que remarquez-vous dans le *user-agent* ?

<details>
<summary>Réponse</summary>

+ `ListAttachedUserPolicies`, `ListUserPolicies` et `ListGroupsForUser` : il cherche **ses propres droits** (policies attachées, policies inline, groupes). Tous ces appels sont refusés : ne connaissant pas ses privilèges, il tente ce qu'il peut.
+ Le user-agent se présente comme **`Botocore/1.34.x Kali Linux/2024.4 …`**, la distribution Linux des pentesteurs. Il est pourtant **incohérent** :
  + il annonce deux versions de Botocore (`1.34.x` puis `1.44…`) ;
  + il annonce un noyau `6.6.9`, alors que l'aws-cli de la même IP annonce `7.0.0`.

  Le user-agent est déclaratif : un attaquant peut l'écrire comme il veut. Ici, il a été **modifié**.
</details>

### Création d'un utilisateur
Parmi ces appels, deux **réussissent** à 15:02:08 :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:00:00 PM") .. datetime("2026-11-17 03:05:00 PM"))
| where EventName in ("CreateUser", "CreateLoginProfile")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RequestParameters, ErrorCode
| sort by TimeGenerated desc
```

+ Quel est le nom du compte créé par *labs-privesc-user* ?
+ À quoi sert `CreateLoginProfile` ?

<details>
<summary>Réponse</summary>

+ **backdoormanAWS**. C'est la signature du même attaquant que *BackdoorMan* dans EntraID (LAB 2).
+ `CreateLoginProfile` donne au nouvel utilisateur un **mot de passe pour la console AWS**, avec `passwordResetRequired: false` : l'attaquant n'aura pas à le changer à la première connexion.

L'attaquant dispose maintenant d'une identité à lui, indépendante de la clé volée : c'est de la **persistance**. Mais ce compte n'a encore aucun droit.
</details>

### Lecture des policies
Juste après, l'attaquant s'intéresse aux policies :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:02:30 PM") .. datetime("2026-11-17 03:10:00 PM"))
| where UserIdentityArn endswith "labs-privesc-user"
| extend rp = parse_json(RequestParameters)
| project TimeGenerated, EventName, ErrorCode, PolicyArn = tostring(rp.policyArn)
| sort by TimeGenerated desc
```

Quels appels échouent ? Quelle policy l'attaquant essaie-t-il de lire ?

<details>
<summary>Réponse</summary>

+ 15:02:50 : une rafale de **`ListPolicies`** réussis. La liste est paginée : il y a plus de 1 000 policies gérées par AWS.
+ 15:05:59 : **`GetUserPolicy`** refusé.
+ 15:07:45 et 15:09:26 : **`GetPolicy`** sur `arn:aws:iam::455764526305:policy/labs-privesc-min`, **réussi**.
+ 15:09:28 : **`GetPolicyVersion`** refusé.

Il essaie de lire **labs-privesc-min**, la policy attachée à sa propre clé.
</details>

Allez voir la définition de cette policy dans la console AWS : compte **Workloads**, **IAM → Policies → labs-privesc-min**, onglet *Permissions* (vous avez les droits de lecture).

+ Quelles actions autorise-t-elle ?
+ Pourquoi `GetPolicy` réussit-il alors que `GetPolicyVersion` échoue ?

<details>
<summary>Réponse</summary>

![Alt text](/img/policy.png)

+ Elle autorise, sur toutes les ressources : `iam:CreateUser`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:AttachUserPolicy`, `iam:CreateLoginProfile` et `iam:UpdateLoginProfile`.
+ `GetPolicy` ne renvoie que les **métadonnées** de la policy : son nom et le numéro de sa version par défaut. Le **contenu**, c'est-à-dire la liste des permissions, se lit avec `GetPolicyVersion`, qui n'est pas autorisé.

L'attaquant ne peut donc pas lire ses propres droits. Mais il a déjà constaté que `CreateUser` fonctionne : il va tenter la suite.
</details>

### Élévation de privilèges
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 03:12:00 PM"))
| where EventName == "AttachUserPolicy"
| extend rp = parse_json(RequestParameters)
| project TimeGenerated, UserIdentityArn, SourceIpAddress, TargetUser = tostring(rp.userName), PolicyArn = tostring(rp.policyArn), ErrorCode
| sort by TimeGenerated desc
```

+ Quelle policy a été attribuée ? À qui ? Qu'est-ce qu'elle lui donne ?
+ Pourquoi le premier appel échoue-t-il ?

<details>
<summary>Réponse</summary>

+ 15:11:19 : *labs-privesc-user* attache la policy **AdministratorAccess** (`arn:aws:iam::aws:policy/AdministratorAccess`) à **backdoormanAWS** : **tous les droits** sur le compte Workloads.
+ 15:11:00 : le premier essai vise **backdoormanv2**, un utilisateur qui n'existe pas (`NoSuchEntityException`). L'attaquant corrige 19 secondes plus tard : il s'agit probablement d'une commande préparée à l'avance, avec le mauvais nom.

*labs-privesc-user* n'était pas administrateur, mais avait le droit de **créer un utilisateur et de lui attacher n'importe quelle policy**. C'est suffisant pour devenir administrateur du compte.
</details>

### Connexion à la console
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 03:20:00 PM"))
| where EventName == "ConsoleLogin"
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, ResponseElements, AdditionalEventData
| sort by TimeGenerated desc
```

Qui se connecte, depuis où, et avec quel niveau de sécurité ?

<details>
<summary>Réponse</summary>

+ 15:13:18 : **backdoormanAWS** se connecte avec succès à la **console AWS**.
+ Depuis **162.0.238.73** avec un navigateur Firefox sous Linux.
+ `MFAUsed: No` : un mot de passe seul suffit.

L'attaquant utilise **deux IPs** : 2.25.8.248 pour les outils en ligne de commande, 162.0.238.73 pour naviguer « à la main ». Il est administrateur du compte, avec un accès qui ne dépend plus de la clé volée.
</details>

###### BONUS
Trouvez des cas d'usages de détection pour ces comportements.
