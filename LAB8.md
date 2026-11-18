# LAB 8 (BONUS) - Accès à un stockage sensible
*Lab autonome, indépendant des précédents.*

> Toutes les heures de ce lab sont en **UTC** (heure de Paris = UTC+1).

### Le stockage Azure
Un **compte de stockage** est une ressource Azure comme une autre (rangée dans une subscription et un groupe de ressources), qui héberge des données. Il s'organise ainsi :
+ **Compte de stockage** : son nom est **unique dans tout Azure** et sert d'adresse (`https://<compte>.blob.core.windows.net`).
+ **Services** : *Blob* (fichiers), *File* (partages réseau), *Queue* et *Table*. Ce lab ne concerne que le service **Blob**.
+ **Conteneur** : un dossier de premier niveau dans le service Blob, l'équivalent d'un bucket S3.
+ **Blob** : le fichier lui-même. Dans les logs, son chemin complet s'écrit `/<compte>/<conteneur>/<blob>`.

On y accède par deux plans distincts :
+ le **plan de contrôle** (Azure Resource Manager) gère la ressource : création, configuration, lecture des **clés d'accès**. Il est tracé dans **AzureActivity** ;
+ le **plan de données** donne accès au contenu, avec une identité Entra ID (rôles *Storage Blob Data …*), une **clé du compte** ou une **SAS** signée avec cette clé. Il est tracé dans **StorageBlobLogs**, si le paramètre de diagnostic du compte est activé.

### Le scénario
L'admin conserve un fichier sensible sur un compte de stockage de la subscription **jazz-pot**. Le compte n'est pas exposé publiquement et personne d'autre que lui n'est censé y accéder. Il a remarqué une activité inhabituelle le **15/11** en début de soirée, entre 19:00 et 19:15, et vous demande de vérifier si le fichier a été consulté.

### Accès aux données
```KQL
StorageBlobLogs
| where TimeGenerated between (datetime("2026-11-15 07:00:00 PM") .. datetime("2026-11-15 07:15:00 PM"))
| project TimeGenerated, OperationName, StatusCode, CallerIpAddress, AuthenticationType, ObjectKey, ResponseBodySize, UserAgentHeader, ReferrerHeader, RequesterUpn, RequesterObjectId
| sort by TimeGenerated desc
```

Quel compte de stockage est concerné ? Quel conteneur, quel fichier ?

<details>
<summary>Réponse</summary>

Le champ **ObjectKey** donne le chemin `/<compte>/<conteneur>/<blob>` :
+ compte de stockage **itsverysecret** (la colonne *AccountName* le donne aussi) ;
+ conteneur **secretcontainer** ;
+ fichier `The secret is there is no secret.txt`.

Vous pouvez le retrouver dans le portail : **Storage accounts → itsverysecret**, dans le groupe de ressources *secret-sauce*.
</details>

Le fichier a-t-il été lu ? Par qui, depuis où, avec quel outil ?

<details>
<summary>Réponse</summary>

+ 19:09:27 : **ListBlobs** sur *secretcontainer*, puis 19:09:43 : **GetBlob** de `The secret is there is no secret.txt` (32 octets) : le fichier a été **listé puis téléchargé**.
+ Depuis **162.0.238.73**, une IP d'hébergeur géolocalisée à Los Angeles.
+ Depuis le **portail Azure** (`ReferrerHeader = https://portal.azure.com/`), avec un navigateur *Firefox 74 sur macOS 10.14*.
+ **Par qui ? Impossible à dire ici** : `RequesterUpn` et `RequesterObjectId` sont vides, car l'authentification est de type **SAS**, pas Entra ID.
</details>

Pour rappel, une SAS (*Shared Access Signature*) est un jeton signé qui donne un accès granulaire et limité dans le temps.

Toutes les lignes ne sont pas des actions de l'utilisateur. Voici quelques indications :
+ `TrustedAccess` depuis une IP privée *10.0.x.x* avec l'user-agent `SRP/1.0` : c'est le **Storage Resource Provider**, le backend Azure qui affiche les propriétés du compte et la liste des conteneurs dans le portail.
+ `BlobPreflightRequest` en `AnonymousPreflight` : la requête **CORS** que le navigateur envoie avant d'appeler le stockage depuis portal.azure.com. Elle n'accède à aucune donnée.

### D'où vient la SAS ?
Regardez la colonne **AuthenticationHash** de la ligne *GetBlob* :
```KQL
StorageBlobLogs
| where TimeGenerated between (datetime("2026-11-15 07:00:00 PM") .. datetime("2026-11-15 07:15:00 PM"))
| where AccountName == "itsverysecret" and OperationName == "GetBlob"
| project TimeGenerated, CallerIpAddress, AuthenticationType, AuthenticationHash
| sort by TimeGenerated desc
```

Avec quoi la SAS a-t-elle été signée ? Qu'est-ce que cela implique ?

<details>
<summary>Réponse</summary>

`AuthenticationHash` commence par **key1(…)** : la SAS a été signée avec la **clé d'accès n°1 du compte de stockage**. Celui qui l'a utilisée possédait donc la clé du compte, qui donne un accès **total** à toutes les données, sans aucun contrôle par le RBAC.

Quand on choisit *Authentication method : Access key* dans le portail, c'est exactement ce qui se passe : le portail récupère la clé, puis signe lui-même des SAS pour naviguer dans les conteneurs.

Un compte de stockage possède **deux** clés, *key1* et *key2*, strictement **équivalentes** : la seconde sert à faire la rotation sans coupure. Les deux donnent un accès total.
</details>

La lecture de la clé, elle, est une opération du **plan de contrôle** : elle passe par Azure Resource Manager et elle est tracée dans les **AzureActivity**. Pivotez sur l'IP et l'heure :
```KQL
AzureActivity
| where TimeGenerated between (datetime("2026-11-15 07:00:00 PM") .. datetime("2026-11-15 07:15:00 PM"))
| where CallerIpAddress == "162.0.238.73" or _ResourceId has "itsverysecret"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
| sort by TimeGenerated desc
```

Qui a récupéré la clé ?

<details>
<summary>Réponse</summary>

19:09:24, soit **3 secondes avant le ListBlobs** : **BackdoorMan@jazz-pot.com** exécute `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` sur *itsverysecret* depuis **162.0.238.73**. Le portail répète l'appel à 19:09:25.

Même IP, quelques secondes d'écart : on peut attribuer le téléchargement à BackdoorMan, alors que les logs du stockage seuls ne le permettaient pas. **Pour un accès par clé ou par SAS, l'identité se trouve dans AzureActivity, pas dans StorageBlobLogs.**
</details>

### Pourquoi était-ce possible ?
La lecture n'a utilisé aucun rôle de données (*Storage Blob Data Reader*…) : elle passe par la clé du compte. Pourquoi un rôle Azure « classique » suffit-il pour lire le fichier ?

<details>
<summary>Réponse</summary>

Les rôles du **plan de contrôle** *Owner* et *Contributor* incluent l'action `listKeys`. Récupérer la clé revient à obtenir un accès **total** aux données : un Contributor peut lire n'importe quel blob, même sans rôle *Data*.
</details>

### À retenir : accéder aux données avec ou sans la clé du compte

| Mode | Comment ça marche | Dans StorageBlobLogs |
|---|---|---|
| **Clé en direct** (*Shared Key*) | L'outil signe **chaque requête** avec la clé du compte | `AuthenticationType = AccountKey` |
| **SAS signée par la clé** | Celui qui détient la clé **calcule lui-même** un jeton (droits, ressource, expiration) signé avec la clé. Azure ne fait que vérifier la signature | `AuthenticationType = SAS`, `AuthenticationHash = key1(…)` ou `key2(…)` |
| **User delegation SAS** | Le jeton est signé avec une clé temporaire obtenue via **Entra ID** : la clé du compte n'est pas utilisée | `AuthenticationType = SAS`, avec l'identité Entra ID de l'utilisateur |

**Ici, nous sommes dans le deuxième cas.** L'attaquant n'a jamais eu de droits sur les données : il a lu la clé par le **plan de contrôle** (`listKeys`, grâce à un rôle Azure classique comme Owner ou Contributor), puis le portail s'en est servi pour signer des SAS et accéder au **plan de données**. Chaque plan laisse ses traces dans sa propre table, et c'est en les recoupant qu'on retrouve l'auteur.

Pour la remédiation : une SAS signée par une clé reste valide **jusqu'à son expiration**. Le seul moyen de l'invalider est de **régénérer la clé**, et comme l'attaquant a pu lire les deux, il faut régénérer **key1 et key2**. La bonne pratique est de n'autoriser que les accès Entra ID (*Allow storage account key access : Disabled*).

###### BONUS
Trouvez des cas d'usages de détection pour ces comportements.
