# LAB 7 - Destruction S3 et EC2
Le LAB 6 a montré que l'attaquant est devenu administrateur du compte **Workloads** le **17/11**, sous l'identité **backdoormanAWS**. Au LAB 5, vous avez peut-être remarqué que les buckets `jazzpot-*` manquaient à l'appel. Il faut maintenant mesurer l'**impact**.

> Toutes les heures de ce lab sont en **UTC** (heure de Paris = UTC+1).

### Ce que GuardDuty a vu
Après l'attaque sur Azure, l'équipe sécurité a ajouté les IPs de l'attaquant à une **liste de menaces** GuardDuty. Au LAB 5, vous avez vu cette liste (*jazzpot-attacker-ips*) dans la configuration de GuardDuty ; voyons ce qu'elle a donné, dans Sentinel, table **AWSGuardDuty** :
```KQL
AWSGuardDuty
| where TimeGenerated between (datetime("2026-11-17 02:00:00 PM") .. datetime("2026-11-17 06:00:00 PM"))
| where AccountId == "455764526305" //Le compte Workloads
| summarize arg_max(TimeGenerated, *) by Id //Derniere version de chaque finding
| summarize Findings = count(), Severite = max(Severity) by ActivityType
| sort by Findings desc
```

Le détail de chaque finding :
```KQL
AWSGuardDuty
| where TimeGenerated between (datetime("2026-11-17 02:00:00 PM") .. datetime("2026-11-17 06:00:00 PM"))
| where AccountId == "455764526305"
| summarize arg_max(TimeGenerated, *) by Id
| extend sd = parse_json(ServiceDetails), rd = parse_json(ResourceDetails)
| project TimeGenerated, ActivityType, Severity, Region, Utilisateur = tostring(rd.accessKeyDetails.userName), IP = tostring(sd.action.awsApiCallAction.remoteIpDetails.ipAddressV4), DernierAppel = tostring(sd.action.awsApiCallAction.api), Occurrences = toint(sd["count"]), Liste = tostring(sd.additionalInfo.threatListName)
| sort by TimeGenerated desc
```

+ Combien de findings ? De quels types, avec quelle sévérité ?
+ Qu'ont-ils **tous** en commun ?

<details>
<summary>Réponse</summary>

+ Une soixantaine de findings :

  | Type | Findings | Sévérité |
  |---|---|---|
  | `Recon:IAMUser/MaliciousIPCaller.Custom` | 34 | 5 (Medium) |
  | `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | 23 | 5 (Medium) |
  | `Discovery:S3/MaliciousIPCaller.Custom` | 3 | **8 (High)** |
  | `UnauthorizedAccess:S3/MaliciousIPCaller.Custom` | 2 | **8 (High)** |

+ Ce sont **tous** des `MaliciousIPCaller.Custom`, avec `Liste = jazzpot-attacker-ips` : ils se déclenchent parce que l'appel vient de **162.0.238.73** ou de **2.25.8.248**, deux IPs que l'équipe a mises dans la liste. Le travail d'investigation sur Azure a donc servi à **alerter** sur AWS.
</details>

Il y a deux pièges de lecture :
+ **Un finding regroupe plusieurs appels.** GuardDuty agrège les appels de même catégorie, pour une même identité et une même IP. `Occurrences` est le total, et `DernierAppel` n'affiche que le **dernier** appel regroupé. Par exemple, le finding de *labs-privesc-user* affiche `AttachUserPolicy` alors qu'il contient surtout la reconnaissance ScoutSuite. Pour compter, on revient à CloudTrail.
+ **La région du finding n'est pas forcément celle de l'appel, et un même appel peut produire plusieurs findings.** GuardDuty a un **détecteur par région**. Les évènements des services globaux (IAM, STS via son point d'accès global) sont journalisés en us-east-1 mais concernent tout le compte : ils sont analysés par le détecteur de **chaque** région activée. Un même appel IAM produit donc un finding en us-east-1 **et** un autre en eu-west-3, avec deux `Id` différents : c'est le cas de l'`AttachUserPolicy` de *labs-privesc-user*. Les évènements régionaux (S3, EC2 à Paris), eux, ne sont vus que par le détecteur de leur région. Le nombre de findings n'est donc pas un nombre d'actions.

### Premières actions d'écriture
Écartons la lecture pour ne garder que les actions de *backdoormanAWS* qui modifient quelque chose. CloudTrail marque chaque évènement avec le champ **ReadOnly** : `true` pour une lecture (`List*`, `Get*`, `Describe*`…), `false` pour une écriture.
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 04:00:00 PM"))
| where UserIdentityArn endswith "backdoormanAWS"
| where ReadOnly == false
| where EventName != "ConsoleLogin" //Marque ReadOnly = false, mais ne modifie rien
| sort by TimeGenerated asc
```

Quelle est la **première** action d'écriture de l'attaquant ?

<details>
<summary>Réponse</summary>

**CreateAccessKey** à 15:17:10, depuis la console (162.0.238.73). Le `TagUser` de la même seconde est ajouté par la console : il enregistre la description de la clé sous forme de tag sur l'utilisateur.
</details>

Combien de clés a-t-il créées ? Lesquelles ?
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 03:30:00 PM"))
| where EventName in ("CreateAccessKey","TagUser")
| extend Cle = extract(@'"accessKeyId":"([A-Z0-9]+)"', 1, tostring(ResponseElements))
| project TimeGenerated, UserIdentityArn, EventName, Cle, RequestParameters, ResponseElements
| sort by TimeGenerated desc
```

<details>
<summary>Quel nom a-t-il donné à ses clés ?</summary>

*Persist* et *DestroyKey*.
</details>

Laquelle utilise-t-il par la suite ? Comment le prouver ? (Reprenez des anciennes KQL et pivotez sur le champ *UserIdentityAccessKeyId*.)

<details>
<summary>Réponse</summary>

| Création | Clé | Utilisation |
|---|---|---|
| 15:17:10 | `AKIAWUHNOYTQQPFE5BVY` | **jamais utilisée** |
| 15:18:01 | `AKIAWUHNOYTQ7KDA6ZLQ` | **507 appels** depuis **2.25.8.248**, de 15:19:00 à 15:20:15 |

```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 04:00:00 PM"))
| where UserIdentityArn endswith "backdoormanAWS" and UserIdentityAccessKeyId startswith "AKIA"
| summarize Appels = count(), Fin = max(TimeGenerated), arg_min(TimeGenerated, EventName, SourceIpAddress, UserAgent) by UserIdentityAccessKeyId
| sort by TimeGenerated desc
```

Le premier appel de la seconde clé est un **GetCallerIdentity** à 15:19:00, depuis le VPS 2.25.8.248 : le même réflexe qu'au début du LAB 6, pour vérifier la nouvelle clé.

La première clé est une **clé dormante** : elle n'apparaît dans aucun log d'utilisation, mais elle reste un accès valide. Un analyste qui ne révoque que les clés **vues en action** la laisse active.

Cette information est également visible sur le portail web :
![Alt text](/img/access_keys.png)
</details>

### Destruction S3
Que s'est-il passé sur S3 ?
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 04:00:00 PM"))
| where UserIdentityArn endswith "backdoormanAWS" and EventSource == "s3.amazonaws.com"
| extend rp = parse_json(RequestParameters)
| summarize Appels = count(), Buckets = dcount(tostring(rp.bucketName)), Debut = min(TimeGenerated), Fin = max(TimeGenerated) by EventName, SourceIpAddress, UserAgent = substring(UserAgent, 0, 40)
| sort by Debut desc
```

Dans quel ordre l'attaquant procède-t-il ? En combien de temps ? Regardez un bucket en particulier :
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:19:00 PM") .. datetime("2026-11-17 03:21:00 PM"))
| extend rp = parse_json(RequestParameters)
| where tostring(rp.bucketName) == "jazzpot-finance-reports-455764526305"
| project TimeGenerated, EventName, Objet = tostring(rp.key), Versioning = tostring(rp.VersioningConfiguration.Status)
| sort by TimeGenerated desc
```

<details>
<summary>Réponse</summary>

+ 15:19:16 : **ListBuckets**, puis pour chacun des **30 buckets** `jazzpot-*` :
  + **ListObjects** et **ListObjectVersions** : il inventorie les fichiers et leurs versions ;
  + **GetObject** de chaque fichier (98 au total) : il **copie** les données ;
  + **DeleteObject** de chaque fichier ;
  + **PutBucketVersioning** avec `Status = Suspended` : il désactive le versioning ;
  + **DeleteBucket**.
+ Les 30 buckets disparaissent entre 15:19:28 et 15:20:15, **en moins d'une minute**. Pour *finance-reports*, tout tient en deux secondes (15:19:46-15:19:47) : c'est un **script**.
+ Il utilise la clé `…7KDA6ZLQ` depuis **2.25.8.248**, avec le même user-agent « Kali » falsifié qu'au LAB 6.

Lire chaque fichier avant de le supprimer, c'est le schéma de la **double extorsion** : copier, détruire, puis réclamer une rançon en menaçant de publier.
</details>

Quel est le dernier objet écrit par l'attaquant ?

<details>
<summary>Réponse</summary>

+ 15:22:33 : **CreateBucket** d'un nouveau bucket **`ransom-455764526305-eu-west-3-an`**, puis **PutBucketEncryption**.
+ 15:23:01 : **PutObject** de **`ransom.txt`** dans ce bucket.

Ces actions sont faites depuis la **console** (162.0.238.73). C'est un scénario de **ransomware cloud** : pas de chiffrement des données, mais destruction et demande de rançon.
</details>

Les données sont-elles récupérables ?

<details>
<summary>Réponse</summary>

Sur S3, sans copie hors du compte, **non** : les objets, leurs versions et les buckets ont été supprimés. La seule protection efficace contre un administrateur malveillant est une sauvegarde **dans un autre compte** (AWS Backup cross-account) ou un verrou **S3 Object Lock** en mode *compliance*.
</details>

### EC2
Qu'a-t-il tenté sur EC2 ?
```KQL
AWSCloudTrail
| where TimeGenerated between (datetime("2026-11-17 03:10:00 PM") .. datetime("2026-11-17 04:00:00 PM"))
| where UserIdentityArn endswith "backdoormanAWS" and EventSource == "ec2.amazonaws.com"
| where EventName !startswith "Describe" and EventName !startswith "Get"
| project TimeGenerated, EventName, SourceIpAddress, RequestParameters, ErrorCode, ErrorMessage
| sort by TimeGenerated desc
```

Cette fois, tentez de retrouver la taille de l'EC2 et le nom de l'instance (tag *Name*).

<details>
<summary>Réponse</summary>

15:25:56 : **RunInstances** d'une **t3a.xlarge** nommée **BIGCRYPTOEC2** (`instanceType` et tag `Name` dans *RequestParameters*), **refusé** (`Client.UnauthorizedOperation`). Le message d'erreur cite un *explicit deny in a service control policy* : la SCP **labs-ec2-allowed-instance-types** (LAB 5) n'autorise que les petits types d'instance. C'est le même réflexe de **cryptominage** que BIGCRYPTOVM dans le LAB 4, et le même résultat : bloqué par un garde-fou, mais tracé.

À la différence d'Azure au LAB 4, CloudTrail conserve les **paramètres de la requête même quand elle est refusée** : on connaît ici la taille et le nom de la machine que l'attaquant voulait lancer.
</details>

<details>
<summary>Une autre action d'écriture, réseau cette fois, semble avoir été effectuée. Laquelle et est-ce une vulnérabilité ?</summary>

15:25:53-15:25:54, **CreateSecurityGroup** `launch-wizard-4` puis **AuthorizeSecurityGroupIngress**, qui ouvre **SSH (TCP 22) à 0.0.0.0/0**, c'est-à-dire à tout Internet.

Piège de lecture : ce groupe de sécurité n'est pas un choix de l'attaquant. C'est le comportement par défaut de l'**assistant de lancement de la console** : au clic sur *Launch instance*, il crée un groupe `launch-wizard-N` avec la règle *Allow SSH traffic from Anywhere* cochée d'office. La description du groupe donne l'heure d'ouverture du formulaire (`launch-wizard-4 created 2026-11-17T15:24:59`). C'est le même phénomène que *PLACEMENTRECOMMENDATIONS* au LAB 4 : l'outil génère des actions à la place de l'utilisateur.

Attention : la création de la machine a échoué, mais le **groupe de sécurité ouvert sur Internet existe toujours**. Involontaire ou non, il fait partie de la remédiation.
</details>

L'attaquant aurait-il pu couper CloudTrail pour effacer ses traces ?

<details>
<summary>Réponse</summary>

Non, le trail CloudTrail étant créé au niveau de l'organisation, cela aurait été impossible pour lui. Qui plus est une des SCPs que vous avez vues au LAB 5 empêche cette suppression locale également.
</details>


### GuardDuty : et sans la liste de menaces ?
Faites le bilan des LAB 6 et 7 : reconnaissance ScoutSuite, création d'un utilisateur, élévation en *AdministratorAccess*, connexion console sans MFA, création de clés, suppression de 30 buckets, tentative de lancement d'une grosse instance. Combien de ces comportements GuardDuty a-t-il détectés **par lui-même**, sans la liste d'IPs ?
```KQL
AWSGuardDuty
| where TimeGenerated between (datetime("2026-11-17 02:00:00 PM") .. datetime("2026-11-17 06:00:00 PM"))
| where AccountId == "455764526305"
| where ActivityType !endswith ".Custom" //On écarte les findings issus de la liste de menaces
| summarize arg_max(TimeGenerated, *) by Id
| project TimeGenerated, AccountId, ActivityType, Severity, Region
```

<details>
<summary>Réponse</summary>

**Aucun.** Sans la liste ajoutée par l'équipe, l'attaque serait passée **inaperçue** : une alerte fondée sur des IOC ne vaut que ce que vaut la liste, et un attaquant qui change d'IP n'est plus vu.

Quelques pistes d'explication :
+ **Pas d'historique.** Les findings comportementaux (`…/AnomalousBehavior`) comparent l'activité à une **référence apprise** sur le compte. GuardDuty a été activé le **15/11**, deux jours avant l'attaque : il n'a pas encore eu le temps d'apprendre ce qui est « normal ».
+ **Des IPs banales.** 2.25.8.248 et 162.0.238.73 sont des serveurs d'hébergeurs, pas des nœuds Tor ni des IPs connues des listes d'AWS : rien ne les signale d'office.
+ **Des actions légitimes en apparence.** `CreateUser`, `AttachUserPolicy` ou `DeleteBucket` sont des opérations d'administration courantes. Prises une par une, et faites par des identités qui en ont le droit, elles ne sont pas suspectes.
+ **Un user-agent maquillé.** GuardDuty sait reconnaître certaines distributions de pentest (`PenTest:IAMUser/KaliLinux`), mais pas ici. ScoutSuite, lui, n'a pas de finding dédié.

GuardDuty est un filet de sécurité, pas une garantie : la détection se construit aussi avec ses **propres règles** sur CloudTrail, dans Sentinel.
</details>

###### BONUS
Trouvez des cas d'usages de détection pour ces comportements.