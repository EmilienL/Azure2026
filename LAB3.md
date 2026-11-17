# LAB 3 - Accès initial et découverte
L'utilisateur *john.coltrane@jazz-pot.com* semble être à l'origine des actions suspectes. Il faudrait déterminer s'il s'agit d'une compromission de son compte ou d'un acte interne malveillant.

> Toutes les heures de ce lab sont en **UTC** (heure de Paris = UTC+1).

### Authentifications suspectes
Regardez dans les SigninLogs de l'utilisateur à la recherche d'indicateurs suspects :
```KQL
SigninLogs
| where TimeGenerated between (datetime("2026-11-15 09:05:00 PM") .. datetime("2026-11-15 09:50:00 PM"))
| where Identity == "John Coltrane"
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, CreatedDateTime, Identity, ResultType, ResultDescription, AppDisplayName, ResourceDisplayName, AuthenticationProtocol, AuthenticationRequirement, ConditionalAccessStatus, IPAddress, City, Country, AutonomousSystemNumber, UserAgent, SessionId
| sort by TimeGenerated desc
```

Que remarquez-vous ?
+ L'utilisateur s'authentifie-t-il depuis des IPs suspectes ?
+ Quel est le type d'hébergement de ces IPs ?
+ Remarquez-vous des différences en user-agent ?
<details>
<summary>Réponse</summary>

+ IPs d'authentification : *162.0.238.73* (géolocalisée à **Los Angeles**, hébergeur) et *2a02:4780:83:7f6e::1* (**VPS** Hostinger en France), alors que John se connecte habituellement depuis une IP résidentielle française (visible à 21:45).
+ Deux user-agents inhabituels : *Firefox 74 sur macOS 10.14* (très ancien) lors de la saisie du mot de passe, puis *Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0* pour tout le reste de l'activité, y compris le device code.
+ Sur le seul événement provenant d'une IP domestique française, John utilise Chrome sur Windows.
</details>

Concernant l'authentification en elle-même :
+ Quel niveau d'authentification a été exigé ?
+ Utilise-t-il des protocoles d'authentification inhabituels ?
+ Les user-agents sont différents, qu'en est-il du **SessionId** ?
<details>
<summary>Réponse</summary>

+ À 21:12, l'authentification se fait **par mot de passe seul** : `AuthenticationRequirement = singleFactorAuthentication` et `ConditionalAccessStatus = notApplied`. Aucune politique d'accès conditionnel n'impose la MFA sur ces applications : le mot de passe a suffi.
+ L'utilisation d'un **Device Code** (21:25, application *Microsoft Azure PowerShell*) est inhabituelle pour un utilisateur lambda.
+ L'ID de session est identique malgré les changements d'*IPs* et de *user-agent*.
</details>

*Il y a un laps de temps entre la première authentification suspecte et celle qui utilise le protocole inhabituel. Commençons par analyser la première.*

<details>
<summary>D'après la KQL précédente, sur quelle application John s'authentifie-t-il ?</summary>

+ La première authentification (21:12) se fait sur *OfficeHome* (le portail Microsoft 365), avec le **mot de passe** de John, depuis 162.0.238.73.
</details>

En additionnant cette information avec les autres indicateurs, une bonne hypothèse serait que John a été victime d'un phishing ou d'un vol d'identifiants. Le proxy de l'attaquant (162.0.238.73) a relayé ces identifiants à Microsoft et récupéré le cookie de session.

Deux points à retenir :
+ Dans un AiTM, **Entra ne voit jamais l'IP de la victime** : c'est le proxy qui s'authentifie à sa place. Que l'IP de John n'apparaisse pas dans cette session est donc normal. On ne verrait l'IP de John dans la même session que si elle était ouverte avant le clic.
+ La MFA n'était **pas exigée** sur le portail Microsoft 365. Un mot de passe volé suffisait, sans même avoir besoin de relayer une MFA.

### Business Email Compromise (BEC)
Pour investiguer un Business Email Compromise, il faut se tourner vers les **Unified Audit Logs** de Microsoft 365 (Exchange, SharePoint, Teams). Ils remontent dans Sentinel via la table **CloudAppEvents** (connecteur Defender XDR) :
```KQL
CloudAppEvents
| where TimeGenerated between (datetime("2026-11-15 09:05:00 PM") .. datetime("2026-11-15 09:30:00 PM"))
| where Application == "Microsoft Exchange Online"
| extend SessionId = RawEventData.AppAccessContext.AADSessionId
| project TimeGenerated, Application, AccountDisplayName, ActionType, IPAddress, SessionId, RawEventData
| sort by TimeGenerated desc
```

Retrouvez toutes les actions illégitimes qu'a effectuées l'attaquant sur la messagerie. Il va falloir creuser dans le champ RawEventData.

<details>
<summary>Réponse</summary>

+ 21:14 : **lecture de l'email malveillant** depuis 162.0.238.73 (*MailItemsAccessed*, même *InternetMessageId* que celui lu par John à 21:08 dans le dossier *Courrier indésirable*)
+ 21:15 : **suppression de l'email malveillant** (*SoftDelete*) depuis 162.0.238.73
+ 21:17 : **redirection d'emails** par inbox rule (*New-InboxRule*) : nommée « ..... », *ForwardTo* = `nobody.actually.likes.jazz@gmail.com`, *StopProcessingRules* = True
</details>

Grâce aux logs d'audit, retrouvez également quelles actions il a faites pour maintenir son accès :
```KQL
AuditLogs
| where TimeGenerated between (datetime("2026-11-15 09:05:00 PM") .. datetime("2026-11-15 09:30:00 PM"))
| where TargetResources contains "bba58a77-0a36-47dd-a579-a37332b69164" //L'objectID de john.coltrane@jazz-pot.com
| extend SourceIP = InitiatedBy.user.ipAddress, OldValue = TargetResources[0].modifiedProperties[0].oldValue, NewValue = TargetResources[0].modifiedProperties[0].newValue
| project TimeGenerated, Category, Identity, SourceIP, OperationName, ResultDescription, AdditionalDetails, OldValue, NewValue
| sort by TimeGenerated desc
```

<details>
<summary>Réponse</summary>

+ 21:21 : **ajout d'un nouveau facteur d'authentification**
</details>

<details>
<summary>Pouvez-vous deviner le modèle de téléphone et le type de facteur d'authentification enregistré ?</summary>

+ **Microsoft Authenticator** d'après les champs *ResultDescription*
+ **iPhone SE (3rd generation)** d'après le champ *NewValue* d'une des traces *Update user* (le champ *StrongAuthenticationPhoneAppDetail* passe de `["iPhone 11"]` à `["iPhone 11","iPhone SE (3rd generation)"]`)
</details>

#### Recherche de secrets sur SharePoint
Dans les SigninLogs, l'attaquant se connecte aussi à **Office 365 SharePoint Online** depuis 162.0.238.73 (21:27). Filtrons les évènements SharePoint et OneDrive de John :
```KQL
CloudAppEvents
| where TimeGenerated between (datetime("2026-11-15 09:20:00 PM") .. datetime("2026-11-15 09:50:00 PM"))
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where AccountDisplayName == "John Coltrane"
| extend R = parse_json(RawEventData), SessionId = RawEventData.AppAccessContext.AADSessionId
| project TimeGenerated, ActionType, AccountDisplayName, IPAddress, Fichier = tostring(R.SourceFileName), ObjectName, Keyword = tostring(R.QueryText), SessionId, UserAgent = tostring(R.UserAgent), RawEventData
| sort by TimeGenerated desc
```

+ Quelles **recherches** l'attaquant a-t-il lancées (*SearchQueryInitiatedSharePoint*) ?
+ Quels **fichiers** a-t-il ouverts ou téléchargés juste après ?
+ Qu'ont en commun les recherches et les noms de fichiers ?

<details>
<summary>Réponse</summary>

**6 recherches en 30 secondes** (21:27:49 → 21:28:19), puis **ouverture des résultats dans la minute** :

| Thème | Recherches | Fichiers ouverts (21:28-21:29) |
|---|---|---|
| Identifiants | `creds`, `credentials` | **AWS_workloads_admin_access_credentials.txt** (ouvert puis **téléchargé** à 21:29:13), vpn_credentials.txt |
| Mots de passe | `mdp`, `mots de passe` | server_passwords.xlsx |
| VPN | `vpn` | vpn_credentials.txt |
| Clés | `akia` (préfixe des clés AWS) | api_keys_inventory.csv, service_accounts_secrets.txt |

Les recherches et les noms de fichiers partagent le même champ lexical : **identifiants, mots de passe, clés**. Ce n'est pas un usage métier, à la limite quelqu'un de trop curieux.

Pièges de lecture :
+ Certains *FileAccessed* viennent d'IPs Microsoft (*20.59.149.x*, *13.80.209.12*) avec l'user-agent **MSWAC** : c'est **Office Online** qui génère l'aperçu du fichier ouvert par l'attaquant.
+ Les fichiers `…_SThumb.jpg` / `_MThumb.jpg` sur OneDrive sont les **photos de profil** de John chargées par l'interface : du bruit.
</details>


En termes d'indicateurs :
+ Quel est le modèle de son téléphone ?
+ Quelle est l'adresse de redirection ?
+ Quel est le sujet de l'email malveillant ?
+ *akia* est une recherche étrange, à quoi correspond-elle ?

<details>
<summary>Réponse</summary>

+ **iPhone SE (3rd generation)** (*StrongAuthenticationPhoneAppDetail* : le téléphone légitime de John est un *iPhone 11*)
+ `nobody.actually.likes.jazz@gmail.com`
+ "Need your help"
+ **AKIA** est le préfixe des *access keys* IAM long terme d'AWS : l'attaquant cherche des clés AWS.
</details>

Passons à la seconde authentification inhabituelle de John (celle par device code).

### Découverte
L'authentification par device code est souvent utilisée par des appliances ou des scripts car elle permet d'éviter l'utilisation de secrets en clair.

```KQL
SigninLogs
| where TimeGenerated between (datetime("2026-11-15 09:05:00 PM") .. datetime("2026-11-15 09:50:00 PM"))
| where Identity == "John Coltrane" and AuthenticationProtocol == "deviceCode"
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, CreatedDateTime, Identity, ResultType, ResultDescription, AppDisplayName, ResourceDisplayName, AuthenticationProtocol, AuthenticationRequirement, ConditionalAccessStatus, IPAddress, City, Country, AutonomousSystemNumber, UserAgent, SessionId
| sort by TimeGenerated desc
```

<details>
<summary>Quelle ressource a été ciblée et par quelle application ?</summary>

L'application *Microsoft Azure PowerShell* (AppId *1950a258-227b-4e31-a9cf-717495945fc2*) a ciblé la ressource *Microsoft Graph*.
</details>

Regardons ce que ce jeton a permis de faire :
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime("2026-11-15 09:20:00 PM") .. datetime("2026-11-15 09:30:00 PM"))
| where UserId == "bba58a77-0a36-47dd-a579-a37332b69164" //L'objectID de john.coltrane@jazz-pot.com
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2" //L'AppId d'Azure PowerShell
| project TimeGenerated, IPAddress, RequestMethod, ResponseStatusCode, RequestUri, UserAgent
| sort by TimeGenerated asc
```

Vous remarquez un pattern assez inhabituel pour un utilisateur lambda, quel outil reconnaissez-vous ?

<details>
<summary>Réponse</summary>

**AzureHound** (*azurehound/v0.0.0*), développé par SpecterOps, permet de collecter des informations sur EntraID (à la manière de SharpHound sur un AD) pour déterminer des chemins d'attaques dans le Cloud.

800 requêtes en **3 secondes** depuis le VPS *2a02:4780:83:7f6e::1*.

```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime("2026-11-15 09:20:00 PM") .. datetime("2026-11-15 09:30:00 PM"))
| where UserId == "bba58a77-0a36-47dd-a579-a37332b69164" //L'objectID de john.coltrane@jazz-pot.com
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2"
| summarize Requetes = count(), Debut = min(TimeGenerated), Fin = max(TimeGenerated) by IPAddress, UserAgent
| sort by Debut desc
```
</details>

Déterminons les informations qu'il a pu acquérir.
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime("2026-11-15 09:20:00 PM") .. datetime("2026-11-15 09:30:00 PM"))
| where UserAgent == "azurehound/v0.0.0"
| extend Endpoint = tostring(split(tostring(parse_url(RequestUri).Path), "/")[2])
| summarize Requetes = count(), Debut = min(TimeGenerated) by Endpoint
| sort by Debut desc
```

Combien d'endpoints différents ont été requêtés ? De quel type de comportement s'agit-il ?
<details>
<summary>Réponse</summary>

8 endpoints, c'est de la **découverte** :
+ servicePrincipals (623)
+ roleManagement (150)
+ applications (13)
+ groups (9)
+ users (2)
+ organization
+ policies
+ devices
</details>

Grâce à ces informations il sait pertinemment quoi cibler : l'énumération des *servicePrincipals* et du *roleManagement* lui a révélé que **John's app** (dont John est propriétaire) détient *RoleManagement.ReadWrite.Directory*. Une minute plus tard (21:26:53), il lui ajoute un secret depuis le portail Azure : c'est le point de départ du LAB 2.


#### BONUS
###### Le vecteur de persistance
Les AuditLogs montrent qu'à 21:21, un nouveau facteur Microsoft Authenticator est enregistré sur le compte de John depuis 162.0.238.73. Or John avait déjà Microsoft Authenticator : pour **ajouter** une méthode, Entra exige de valider une méthode **existante**.
```KQL
SigninLogs
//Certains sign-ins sont ingérés avec beaucoup de retard : on filtre sur l'heure réelle (CreatedDateTime)
| where TimeGenerated between (datetime("2026-11-15 09:15:00 PM") .. datetime("2026-11-15 10:30:00 PM"))
| where CreatedDateTime between (datetime("2026-11-15 09:18:00 PM") .. datetime("2026-11-15 09:22:00 PM"))
| where Identity == "John Coltrane"
| mv-expand Etape = parse_json(AuthenticationDetails)
| project CreatedDateTime, TimeGenerated, AppDisplayName, IPAddress, AuthenticationRequirement, Methode = tostring(Etape.authenticationMethod), Detail = tostring(Etape.authenticationStepResultDetail), SessionId
| sort by CreatedDateTime desc
```

Que s'est-il passé entre 21:18 et 21:21 pour que l'attaquant puisse enregistrer son propre téléphone ?

<details>
<summary>Réponse</summary>

+ À 21:18:47 (*My Profile*) et 21:19:26 (*My Signins*), la session est encore en `singleFactorAuthentication`.
+ À 21:19:51 (*My Signins*), la session passe en `multiFactorAuthentication` : **Mobile app notification**, *MFA completed in Azure AD*. À cette heure-là, le seul téléphone enregistré est l'**iPhone 11 de John** (l'iPhone SE n'est ajouté qu'à 21:21:17) : c'est **John qui a validé** la notification.
+ Piège : cette ligne n'est ingérée qu'à 21:49 puis à nouveau à 22:12 (*TimeGenerated*). En filtrant sur *TimeGenerated*, on croit à tort à des validations MFA ultérieures.
+ Les logs prouvent la validation mais ne peuvent indiquer la raison. Des cas réels mentionnent des appels du « support informatique » pour « finaliser une mise à jour de sécurité de son compte » par exemple.
+ C'est de l'**ingénierie sociale par téléphone (vishing)**. Avec le *number matching* d'Authenticator, bombarder la victime de notifications (*MFA fatigue*) ne suffit plus : l'attaquant doit lui communiquer le nombre, donc lui parler. C'est le mode opératoire de groupes comme *Scattered Spider* ou *Lapsus$*.
+ À partir de 21:21, l'attaquant n'a plus besoin de John : il a **son propre téléphone** enregistré sur le compte.

Remédiation : une MFA par notification reste **phishable**. Seules les méthodes résistantes au phishing (FIDO2, passkeys, Windows Hello) l'empêchent, en particulier pour l'action *Register security information*, qu'une politique d'accès conditionnel peut protéger.
</details>

Le même iPhone SE (3rd generation) apparaît-il ailleurs dans le tenant ? Qu'est-ce que cela prouve ?

<details>
<summary>Réponse</summary>

Oui : à 21:33, **BackdoorMan@jazz-pot.com** enregistre Microsoft Authenticator sur un *iPhone SE (3rd generation)*, depuis la même IP 162.0.238.73. C'est le même attaquant derrière la compromission de John et la création du compte du LAB 2.
</details>

###### Détection

Trouvez des cas d'usages de détection pour ces comportements.
