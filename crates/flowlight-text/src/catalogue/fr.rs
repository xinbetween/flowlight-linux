//! Français. Une traduction de l'original anglais, pas encore relue par une personne de langue maternelle.

/// Chaque phrase, dans l'ordre où elle apparaît à l'écran.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "Ce texte est une traduction et n'a pas encore été relu par une personne de langue maternelle. \
         Flowlight est testé sur la formulation anglaise ; en cas de divergence, c'est l'anglais qui décrit ce \
         que fait le programme.",
    ),
    ("days.one", "{count} jour"),
    ("days.many", "{count} jours"),
    (
        "retention.describe",
        "les requêtes individuelles sont conservées {detail}, et un résumé quotidien {summary}",
    ),
    ("field.at", "quand"),
    ("field.process", "le processus"),
    ("field.confidence", "comment le processus a été nommé"),
    ("field.pid", "l'identifiant du processus"),
    ("field.agent", "l'agent"),
    ("field.direction", "le sens du trafic"),
    ("field.host", "l'hôte"),
    ("field.method", "la méthode"),
    ("field.target", "le chemin"),
    ("field.status", "le statut"),
    ("field.bytes", "la taille"),
    ("field.protocol", "le protocole"),
    ("field.rpc_method", "la méthode MCP"),
    ("field.rpc_tool", "le nom de l'outil"),
    (
        "export.destination.none",
        "Aucune destination n'est définie, donc rien ne peut être envoyé où que ce soit.",
    ),
    (
        "export.destination.otlp",
        "Chaque requête que Flowlight lit sera envoyée sur le réseau vers {destination}, en OTLP.",
    ),
    (
        "export.destination.file",
        "Chaque requête que Flowlight lit sera écrite dans {destination}, une ligne par requête. Rien ne \
         traverse le réseau.",
    ),
    (
        "export.destination.unusable",
        "{destination} n'est ni un collecteur ni un chemin de fichier absolu, donc rien ne peut y être envoyé.",
    ),
    (
        "export.fields.none",
        "Aucun champ ne circule, ce qui signifie que chaque enregistrement ne dirait rien du tout.",
    ),
    ("export.fields.one", "{count} champ circule : {fields}."),
    ("export.fields.many", "{count} champs circulent : {fields}."),
    ("export.withheld", "Ceux-ci non : {fields}."),
    (
        "export.headers.one",
        "{count} en-tête est envoyé avec chaque lot : {names}. Les valeurs ne sont pas montrées ici et ne font \
         pas partie de ce que vous acceptez.",
    ),
    (
        "export.headers.many",
        "{count} en-têtes sont envoyés avec chaque lot : {names}. Les valeurs ne sont pas montrées ici et ne \
         font pas partie de ce que vous acceptez.",
    ),
    (
        "export.bound",
        "Cet accord porte exactement là-dessus. Changer la destination, les champs ou les en-têtes arrête \
         l'export jusqu'à ce que quelqu'un accepte de nouveau.",
    ),
    ("export.why.off", "L'export est désactivé."),
    (
        "export.why.nowhere",
        "Aucune destination n'est définie, donc il n'y a nulle part où envoyer quoi que ce soit.",
    ),
    (
        "export.why.unusable",
        "La destination n'est ni un collecteur http:// ou https:// ni un chemin de fichier absolu, donc on ne \
         sait pas ce qu'y envoyer signifierait.",
    ),
    (
        "export.why.unagreed",
        "Personne n'a encore accepté cela. Rien n'est envoyé avant que quelqu'un accepte.",
    ),
    (
        "export.why.changed",
        "Ce qui est envoyé, ou vers où, a changé depuis que quelqu'un a accepté. Rien n'est envoyé avant que \
         quelqu'un accepte ce qui est prévu maintenant.",
    ),
    (
        "ask.none",
        "Aucun modèle n'est configuré, donc aucune question ne peut être traitée. Flowlight pour Linux n'a pas \
         de modèle à lui : aucun poids n'est fourni et aucune valeur par défaut ne pointe vers l'API de qui que \
         ce soit.",
    ),
    (
        "ask.remote",
        "Votre question et les résultats des requêtes que Flowlight exécute pour elle seront envoyés à \
         {endpoint}.",
    ),
    (
        "ask.local",
        "Votre question part vers {endpoint}, qui se trouve sur cette machine ou sur ce réseau. Rien ne \
         traverse internet.",
    ),
    (
        "ask.sent",
        "Ce qui est envoyé, c'est la question, les instructions, et les totaux et les noms que renvoient les \
         propres requêtes de Flowlight. Jamais une ligne d'historique, jamais le chemin d'une requête, et jamais \
         quelque chose que le modèle n'a pas demandé.",
    ),
    (
        "ask.queries",
        "Le modèle ne voit pas la base de données. Il peut nommer une requête parmi une liste fixe, que \
         Flowlight exécute ; il n'y a pas de langage de requête et aucun moyen d'en écrire une.",
    ),
    (
        "ask.recorded",
        "La connexion vers le fournisseur est enregistrée et attribuée à flowlightd, comme celle de n'importe \
         quel autre processus. Un outil qui cacherait son propre trafic n'aurait pas à montrer celui des \
         autres.",
    ),
    (
        "ask.kind.local",
        "un serveur de modèles sur cette machine ou sur ce réseau",
    ),
    ("ask.kind.compatible", "un point d'accès compatible OpenAI"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} convient."),
    ("ask.safety.not_a_url", "{endpoint} n'est pas une URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} n'est ni une adresse http:// ni une adresse https://.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} est du http:// en clair vers une adresse qui n'est ni cette machine ni un réseau privé. Une \
         clé et une question sur le trafic de cette machine traverseraient le réseau en clair, donc Flowlight \
         ne les envoie pas. Utilisez https://.",
    ),
    (
        "intercept.watching",
        "L'interception n'est pas de l'observation. Tout le reste de ce que fait Flowlight lit ce qu'une \
         application remet à sa bibliothèque TLS et ne change rien de ce qui traverse le réseau.",
    ),
    (
        "intercept.agents.none",
        "Aucun agent n'est nommé, donc rien n'est redirigé. L'interception s'applique aux agents qu'elle nomme \
         et à rien d'autre sur cette machine.",
    ),
    (
        "intercept.agents",
        "Les connexions de {agents} — et de tout ce qu'ils lancent — sont redirigées vers un proxy sur cette \
         machine, qui termine TLS et ouvre sa propre connexion vers l'extérieur.",
    ),
    (
        "intercept.authority",
        "Ce proxy présente un certificat signé par une autorité de certification créée sur cette machine. Tout \
         ce qui ne lui fait pas confiance refusera la connexion, ce qui est précisément le rôle d'un certificat \
         épinglé.",
    ),
    (
        "intercept.passthrough",
        "Un hôte pour lequel personne n'a écrit de mock passe sans être terminé du tout, si bien que le \
         certificat n'est présenté que là où il y a une raison de le faire.",
    ),
    (
        "intercept.never",
        "Ceux-ci ne sont jamais terminés, quoi qu'en dise le reste : {hosts}.",
    ),
    (
        "intercept.off",
        "La désactiver arrête la redirection immédiatement. Retirer l'autorité de certification est une étape \
         distincte, car lui faire confiance et lui retirer cette confiance sont deux choses que l'on devrait \
         faire exprès.",
    ),
    (
        "owners.what",
        "Flowlight va demander qui exploite les adresses auxquelles cette machine s'est connectée.",
    ),
    (
        "owners.question",
        "La question est une requête DNS sur les données de routage publiques de Team Cymru, envoyée à \
         {resolver} — le résolveur de cette machine, ou un résolveur public si elle n'en a aucun de configuré.",
    ),
    (
        "owners.sent",
        "Ce qui est envoyé, c'est une adresse. Pas quel processus l'a atteinte, ni quand, ni combien de fois, \
         ni rien d'autre que Flowlight sait à son sujet.",
    ),
    (
        "owners.local",
        "Une adresse de cette machine ou de ce réseau n'est jamais demandée : la réponse est déjà connue, et la \
         question porterait sur votre réseau.",
    ),
    (
        "owners.rate",
        "Quatre adresses par minute au maximum, les plus actives d'abord, et jamais deux fois la même.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask est désactivé. Flowlight pour Linux n'a pas de modèle, il faut donc en configurer un : `flowlightd model --kind local --model <name>` pour un serveur sur cette machine, ou un fournisseur et une clé.",
    ),
    (
        "ask.why.no_endpoint",
        "Aucun point d'accès n'est défini, il n'y a donc rien à interroger.",
    ),
    (
        "ask.why.no_model",
        "Aucun nom de modèle n'est défini. Il faut indiquer à chaque fournisseur quel modèle utiliser, et il n'y a pas de valeur par défaut raisonnable à deviner.",
    ),
    (
        "ask.why.no_key",
        "{kind} demande une clé, et il n'y en a aucune enregistrée.",
    ),
    ("ask.why.unconfigured", "Ask n'est pas configuré."),
    (
        "intercept.why.off",
        "L'interception est désactivée. Rien n'est terminé, et aucun certificat de Flowlight n'est présenté à quoi que ce soit.",
    ),
    (
        "intercept.why.no_agents",
        "L'interception est activée et ne nomme aucun agent, donc rien n'est redirigé. En nommer un est la façon de choisir la portée : `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "un résolveur public"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "Les contenus ne sont pas lus du tout. Les connexions restent attribuées.",
    ),
    (
        "budget.session.expired",
        "La capture des contenus est arrivée à son terme et ne lit plus rien. Renouvelez-la pour recommencer.",
    ),
    (
        "budget.session.remaining",
        "Les contenus seront encore lus pendant {remaining}.",
    ),
    (
        "budget.session.unlimited",
        "Les contenus sont lus, sans limite de session — ce qui a été demandé, non supposé.",
    ),
    (
        "budget.daily.none",
        "Il n'y a pas de plafond journalier sur ce qu'un seul processus peut contribuer.",
    ),
    (
        "budget.daily",
        "Passé {size} sur une journée, les contenus d'un processus ne sont plus capturés jusqu'au lendemain.",
    ),
    (
        "budget.paths.full",
        "Les chemins des requêtes sont conservés en entier, débarrassés des identifiants qu'ils contenaient.",
    ),
    (
        "budget.paths.host",
        "Seul l'hôte d'une requête est conservé, jamais le chemin demandé.",
    ),
    (
        "budget.paths.none",
        "Ni les chemins ni les chaînes de requête ne sont conservés. Les hôtes le sont, car sans eux rien ne peut être regroupé.",
    ),
    (
        "budget.retention",
        "Les requêtes individuelles sont conservées {detail}, et un résumé quotidien {summary}.",
    ),
    ("time.seconds.one", "{count} seconde"),
    ("time.seconds.many", "{count} secondes"),
    ("time.minutes.one", "{count} minute"),
    ("time.minutes.many", "{count} minutes"),
    ("time.hours.one", "{count} heure"),
    ("time.hours.many", "{count} heures"),
    ("time.joined", "{hours} et {minutes}"),
    ("size.bytes", "{count} octets"),
    // The channels that are not the network.
    (
        "devices.channels",
        "Voici les canaux qui ne sont pas le réseau : ce qui est branché en USB, ce qui est appairé en Bluetooth, et quels volumes amovibles sont montés.",
    ),
    (
        "devices.no_bytes",
        "Ce qui est rapporté, c'est ce qui est connecté et quand cela a changé. Jamais combien y est passé : Linux ne comptabilise pas les octets par périphérique d'une manière attribuable à un processus, et un chiffre que personne ne peut assumer est pire que pas de chiffre.",
    ),
    (
        "devices.sources",
        "Tout est lu dans les fichiers que le noyau publie déjà dans /sys et /proc. Aucun service système n'est interrogé, et rien ne quitte cette machine.",
    ),
    (
        "devices.off",
        "Désactivé jusqu'à ce qu'on le demande — non pas faute d'une permission, mais parce que cela élargit ce qui est observé.",
    ),
];
