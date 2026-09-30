//! Italiano. Una traduzione dell'originale inglese, non ancora riletta da una persona di lingua madre.

/// Ogni frase, nell'ordine in cui appare sullo schermo.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "Questo testo è una traduzione e non è ancora stato riletto da una persona di lingua madre. Flowlight \
         viene testato sulla formulazione inglese; dove le due divergono, è l'inglese a dire che cosa fa il \
         programma.",
    ),
    ("days.one", "{count} giorno"),
    ("days.many", "{count} giorni"),
    (
        "retention.describe",
        "le singole richieste vengono conservate per {detail}, e un riepilogo giornaliero per {summary}",
    ),
    ("field.at", "quando"),
    ("field.process", "il processo"),
    ("field.confidence", "come è stato nominato il processo"),
    ("field.pid", "l'identificatore del processo"),
    ("field.agent", "l'agente"),
    ("field.direction", "la direzione del traffico"),
    ("field.host", "l'host"),
    ("field.method", "il metodo"),
    ("field.target", "il percorso"),
    ("field.status", "lo stato"),
    ("field.bytes", "la dimensione"),
    ("field.protocol", "il protocollo"),
    ("field.rpc_method", "il metodo MCP"),
    ("field.rpc_tool", "il nome dello strumento"),
    (
        "export.destination.none",
        "Non è impostata nessuna destinazione, quindi non può essere inviato nulla da nessuna parte.",
    ),
    (
        "export.destination.otlp",
        "Ogni richiesta che Flowlight legge verrà inviata in rete a {destination}, come OTLP.",
    ),
    (
        "export.destination.file",
        "Ogni richiesta che Flowlight legge verrà scritta in {destination}, una riga per richiesta. Niente \
         attraversa la rete.",
    ),
    (
        "export.destination.unusable",
        "{destination} non è né un collector né un percorso di file assoluto, quindi non può essere inviato \
         nulla lì.",
    ),
    (
        "export.fields.none",
        "Non viaggia nessun campo, il che significa che ogni record non direbbe assolutamente niente.",
    ),
    ("export.fields.one", "Viaggia {count} campo: {fields}."),
    ("export.fields.many", "Viaggiano {count} campi: {fields}."),
    ("export.withheld", "Questi no: {fields}."),
    (
        "export.headers.one",
        "Con ogni lotto viene inviata {count} intestazione: {names}. I valori non sono mostrati qui e non fanno \
         parte di ciò a cui si sta acconsentendo.",
    ),
    (
        "export.headers.many",
        "Con ogni lotto vengono inviate {count} intestazioni: {names}. I valori non sono mostrati qui e non \
         fanno parte di ciò a cui si sta acconsentendo.",
    ),
    (
        "export.bound",
        "Questo consenso riguarda esattamente quello. Cambiare la destinazione, i campi o le intestazioni ferma \
         l'export finché qualcuno non acconsente di nuovo.",
    ),
    ("export.why.off", "L'export è disattivato."),
    (
        "export.why.nowhere",
        "Non è impostata nessuna destinazione, quindi non c'è nessun posto dove inviare qualcosa.",
    ),
    (
        "export.why.unusable",
        "La destinazione non è né un collector http:// o https:// né un percorso di file assoluto, quindi non è \
         chiaro cosa significherebbe inviarvi qualcosa.",
    ),
    (
        "export.why.unagreed",
        "Nessuno ha ancora acconsentito a questo. Non viene inviato niente finché qualcuno non acconsente.",
    ),
    (
        "export.why.changed",
        "Ciò che viene inviato, o dove, è cambiato da quando qualcuno ha acconsentito. Non viene inviato niente \
         finché qualcuno non acconsente a com'è adesso.",
    ),
    (
        "ask.none",
        "Non è configurato nessun modello, quindi non è possibile rispondere a domande. Flowlight per Linux non \
         ha un modello proprio: non include pesi e non ha un valore predefinito che punti all'API di qualcuno.",
    ),
    (
        "ask.remote",
        "La tua domanda e i risultati delle interrogazioni che Flowlight esegue per essa verranno inviati a \
         {endpoint}.",
    ),
    (
        "ask.local",
        "La tua domanda va a {endpoint}, che si trova su questa macchina o su questa rete. Niente attraversa \
         internet.",
    ),
    (
        "ask.sent",
        "Ciò che viene inviato è la domanda, le istruzioni e i totali e i nomi che restituiscono le \
         interrogazioni di Flowlight. Mai una riga di cronologia, mai il percorso di una richiesta e mai niente \
         che il modello non abbia chiesto.",
    ),
    (
        "ask.queries",
        "Il modello non vede il database. Può nominare una interrogazione di un elenco fisso, che Flowlight \
         esegue; non c'è un linguaggio di interrogazione né alcun modo di scriverne uno.",
    ),
    (
        "ask.recorded",
        "La connessione verso il fornitore viene registrata e attribuita a flowlightd, come quella di qualsiasi \
         altro processo. Uno strumento che nascondesse il proprio traffico non avrebbe motivo di mostrare quello \
         di altri.",
    ),
    (
        "ask.kind.local",
        "un server di modelli su questa macchina o su questa rete",
    ),
    ("ask.kind.compatible", "un endpoint compatibile con OpenAI"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} va bene."),
    ("ask.safety.not_a_url", "{endpoint} non è una URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} non è né un indirizzo http:// né un indirizzo https://.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} è http:// in chiaro verso un indirizzo che non è questa macchina né una rete privata. Una \
         chiave e una domanda sul traffico di questa macchina attraverserebbero la rete in chiaro, quindi \
         Flowlight non le invia. Usa https://.",
    ),
    (
        "intercept.watching",
        "L'intercettazione non è osservazione. Tutto il resto di ciò che Flowlight fa legge quello che \
         un'applicazione consegna alla sua libreria TLS e non cambia niente di ciò che attraversa la rete.",
    ),
    (
        "intercept.agents.none",
        "Non è nominato nessun agente, quindi non viene reindirizzato niente. L'intercettazione si applica agli \
         agenti che nomina e a nient'altro su questa macchina.",
    ),
    (
        "intercept.agents",
        "Le connessioni di {agents} — e di tutto ciò che essi avviano — vengono reindirizzate a un proxy su \
         questa macchina, che termina il TLS e apre una propria connessione verso l'esterno.",
    ),
    (
        "intercept.authority",
        "Quel proxy presenta un certificato firmato da un'autorità di certificazione creata su questa macchina. \
         Tutto ciò che non si fida di essa rifiuterà la connessione, che è esattamente quello che un certificato \
         vincolato deve fare.",
    ),
    (
        "intercept.passthrough",
        "Un host per cui nessuno ha scritto un mock passa senza essere terminato affatto, così il certificato \
         viene presentato solo dove c'è una ragione per farlo.",
    ),
    (
        "intercept.never",
        "Questi non vengono mai terminati, qualunque cosa dica il resto: {hosts}.",
    ),
    (
        "intercept.off",
        "Disattivarla ferma il reindirizzamento immediatamente. Rimuovere l'autorità di certificazione è un \
         passo a parte, perché fidarsi di una e togliere quella fiducia sono entrambe cose che si dovrebbero \
         fare di proposito.",
    ),
    (
        "owners.what",
        "Flowlight chiederà chi gestisce gli indirizzi a cui questa macchina si è connessa.",
    ),
    (
        "owners.question",
        "La domanda è una interrogazione DNS dei dati di routing pubblici di Team Cymru, inviata a {resolver} — \
         il resolver di questa macchina, o uno pubblico se non ne ha nessuno configurato.",
    ),
    (
        "owners.sent",
        "Ciò che viene inviato è un indirizzo. Non quale processo lo ha raggiunto, non quando, non quanto \
         spesso e nient'altro che Flowlight sappia al riguardo.",
    ),
    (
        "owners.local",
        "Di un indirizzo su questa macchina o su questa rete non si chiede mai: la risposta è già nota, e la \
         domanda riguarderebbe la tua rete.",
    ),
    (
        "owners.rate",
        "Al massimo quattro indirizzi al minuto, prima i più attivi, e mai due volte lo stesso.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask è disattivato. Flowlight per Linux non ha un modello, quindi bisogna configurarne uno: `flowlightd model --kind local --model <name>` per un server su questa macchina, oppure un fornitore e una chiave.",
    ),
    (
        "ask.why.no_endpoint",
        "Non è impostato nessun endpoint, quindi non c'è niente a cui chiedere.",
    ),
    (
        "ask.why.no_model",
        "Non è impostato nessun nome di modello. A ogni fornitore va detto quale modello usare, e non c'è un valore predefinito sensato da indovinare.",
    ),
    (
        "ask.why.no_key",
        "{kind} richiede una chiave, e non ce n'è nessuna salvata.",
    ),
    ("ask.why.unconfigured", "Ask non è configurato."),
    (
        "intercept.why.off",
        "L'intercettazione è disattivata. Non viene terminato niente, e nessun certificato di Flowlight viene presentato a nulla.",
    ),
    (
        "intercept.why.no_agents",
        "L'intercettazione è attiva e non nomina alcun agente, quindi non viene reindirizzato niente. Nominarne uno è il modo di scegliere l'ambito: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "un resolver pubblico"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "I contenuti non vengono letti affatto. Le connessioni continuano a essere attribuite.",
    ),
    (
        "budget.session.expired",
        "La cattura dei contenuti è esaurita e non legge più niente. Rinnovala per ricominciare.",
    ),
    (
        "budget.session.remaining",
        "I contenuti verranno letti per altri {remaining}.",
    ),
    (
        "budget.session.unlimited",
        "I contenuti vengono letti, senza limite di sessione — cosa che è stata chiesta, non data per scontata.",
    ),
    (
        "budget.daily.none",
        "Non c'è un tetto giornaliero a quanto un singolo processo può contribuire.",
    ),
    (
        "budget.daily",
        "Dopo {size} in un giorno, di un processo non vengono più catturati i contenuti fino al giorno seguente.",
    ),
    (
        "budget.paths.full",
        "I percorsi delle richieste sono conservati per intero, con le credenziali rimosse.",
    ),
    (
        "budget.paths.host",
        "Viene conservato solo l'host di una richiesta, mai il percorso che ha chiesto.",
    ),
    (
        "budget.paths.none",
        "Non vengono conservati né i percorsi né le stringhe di query. Gli host sì, perché senza di essi non si può raggruppare niente.",
    ),
    (
        "budget.retention",
        "Le singole richieste sono conservate per {detail}, e un riepilogo giornaliero per {summary}.",
    ),
    ("time.seconds.one", "{count} secondo"),
    ("time.seconds.many", "{count} secondi"),
    ("time.minutes.one", "{count} minuto"),
    ("time.minutes.many", "{count} minuti"),
    ("time.hours.one", "{count} ora"),
    ("time.hours.many", "{count} ore"),
    ("time.joined", "{hours} e {minutes}"),
    ("size.bytes", "{count} byte"),
    // The channels that are not the network.
    (
        "devices.channels",
        "Questi sono i canali che non sono la rete: cosa è collegato via USB, cosa è accoppiato via Bluetooth e quali volumi rimovibili sono montati.",
    ),
    (
        "devices.no_bytes",
        "Viene riportato cosa è collegato e quando è cambiato. Mai quanto è passato attraverso: Linux non contabilizza i byte per dispositivo in un modo attribuibile a un processo, e un numero di cui nessuno può rispondere è peggio di nessun numero.",
    ),
    (
        "devices.sources",
        "Tutto è letto dai file che il kernel già pubblica in /sys e /proc. Non si interroga alcun servizio di sistema, e niente lascia questa macchina.",
    ),
    (
        "devices.off",
        "Disattivato finché non viene richiesto — non perché manchi un permesso, ma perché allarga ciò che viene osservato.",
    ),
];
