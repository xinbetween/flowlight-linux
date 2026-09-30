//! Deutsch. Eine Übersetzung des englischen Originals, noch nicht von einer Muttersprachlerin oder einem
//! Muttersprachler geprüft.

/// Jeder Satz, in der Reihenfolge, in der er auf dem Bildschirm erscheint.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "Dieser Text ist eine Übersetzung und wurde noch nicht von einer Muttersprachlerin oder einem \
         Muttersprachler geprüft. Flowlight wird gegen die englische Fassung getestet; wo beide voneinander \
         abweichen, gilt das englische Wort für das, was das Programm tut.",
    ),
    ("days.one", "{count} Tag"),
    ("days.many", "{count} Tage"),
    (
        "retention.describe",
        "einzelne Anfragen werden {detail} aufbewahrt, eine Tageszusammenfassung {summary}",
    ),
    ("field.at", "wann"),
    ("field.process", "der Prozess"),
    ("field.confidence", "wie der Prozess benannt wurde"),
    ("field.pid", "die Prozesskennung"),
    ("field.agent", "der Agent"),
    ("field.direction", "die Richtung"),
    ("field.host", "der Host"),
    ("field.method", "die Methode"),
    ("field.target", "der Pfad"),
    ("field.status", "der Status"),
    ("field.bytes", "die Größe"),
    ("field.protocol", "das Protokoll"),
    ("field.rpc_method", "die MCP-Methode"),
    ("field.rpc_tool", "der Name des Werkzeugs"),
    (
        "export.destination.none",
        "Es ist kein Ziel festgelegt, also kann nichts irgendwohin gesendet werden.",
    ),
    (
        "export.destination.otlp",
        "Jede Anfrage, die Flowlight liest, wird als OTLP über das Netzwerk an {destination} gesendet.",
    ),
    (
        "export.destination.file",
        "Jede Anfrage, die Flowlight liest, wird nach {destination} geschrieben, eine Zeile je Anfrage. Nichts \
         verlässt diesen Rechner.",
    ),
    (
        "export.destination.unusable",
        "{destination} ist weder ein Collector noch ein absoluter Dateipfad, also kann nichts dorthin gesendet \
         werden.",
    ),
    (
        "export.fields.none",
        "Es wird kein Feld übertragen, womit jeder Datensatz überhaupt nichts aussagen würde.",
    ),
    (
        "export.fields.one",
        "{count} Feld wird übertragen: {fields}.",
    ),
    (
        "export.fields.many",
        "{count} Felder werden übertragen: {fields}.",
    ),
    ("export.withheld", "Diese nicht: {fields}."),
    (
        "export.headers.one",
        "{count} Header wird mit jedem Stapel gesendet: {names}. Die Werte werden hier nicht gezeigt und sind \
         nicht Teil dessen, wozu Sie zustimmen.",
    ),
    (
        "export.headers.many",
        "{count} Header werden mit jedem Stapel gesendet: {names}. Die Werte werden hier nicht gezeigt und \
         sind nicht Teil dessen, wozu Sie zustimmen.",
    ),
    (
        "export.bound",
        "Diese Zustimmung gilt genau dafür. Wird das Ziel, die Felder oder die Header geändert, hält der \
         Export an, bis erneut jemand zustimmt.",
    ),
    ("export.why.off", "Der Export ist ausgeschaltet."),
    (
        "export.why.nowhere",
        "Es ist kein Ziel festgelegt, also gibt es nichts, wohin gesendet werden könnte.",
    ),
    (
        "export.why.unusable",
        "Das Ziel ist weder ein http://- oder https://-Collector noch ein absoluter Dateipfad, also ist nicht \
         klar, was Senden dorthin bedeuten würde.",
    ),
    (
        "export.why.unagreed",
        "Dem hat noch niemand zugestimmt. Es wird nichts gesendet, bis jemand zustimmt.",
    ),
    (
        "export.why.changed",
        "Was gesendet wird oder wohin, hat sich geändert, seit jemand zugestimmt hat. Es wird nichts gesendet, \
         bis jemand dem jetzigen Stand zustimmt.",
    ),
    (
        "ask.none",
        "Es ist kein Modell eingerichtet, also können keine Fragen beantwortet werden. Flowlight für Linux hat \
         kein eigenes Modell: es bringt keine Gewichte mit und zeigt standardmäßig auf niemandes API.",
    ),
    (
        "ask.remote",
        "Ihre Frage und die Ergebnisse der Abfragen, die Flowlight dafür ausführt, werden an {endpoint} \
         gesendet.",
    ),
    (
        "ask.local",
        "Ihre Frage geht an {endpoint}, das auf diesem Rechner oder in diesem Netzwerk liegt. Nichts geht ins \
         Internet.",
    ),
    (
        "ask.sent",
        "Gesendet werden die Frage, die Anweisungen und die Summen und Namen, die Flowlights eigene Abfragen \
         zurückgeben. Niemals eine Zeile aus dem Verlauf, niemals das Ziel einer Anfrage und niemals etwas, \
         wonach das Modell nicht gefragt hat.",
    ),
    (
        "ask.queries",
        "Das Modell sieht die Datenbank nicht. Es darf eine aus einer festen Liste von Abfragen nennen, die \
         Flowlight dann ausführt; es gibt keine Abfragesprache und keine Möglichkeit, eine zu schreiben.",
    ),
    (
        "ask.recorded",
        "Die Verbindung zum Anbieter wird aufgezeichnet und flowlightd zugeordnet, wie die jedes anderen \
         Prozesses. Ein Werkzeug, das seinen eigenen Verkehr verbirgt, hätte kein Recht, den von anderen zu \
         zeigen.",
    ),
    (
        "ask.kind.local",
        "ein Modellserver auf diesem Rechner oder in diesem Netzwerk",
    ),
    ("ask.kind.compatible", "ein OpenAI-kompatibler Endpunkt"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} ist in Ordnung."),
    ("ask.safety.not_a_url", "{endpoint} ist keine URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} ist weder eine http://- noch eine https://-Adresse.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} ist einfaches http:// an eine Adresse, die weder dieser Rechner noch ein privates Netzwerk \
         ist. Ein Schlüssel und eine Frage über den Verkehr dieses Rechners würden unverschlüsselt über das \
         Netzwerk gehen, deshalb sendet Flowlight sie nicht. Verwenden Sie https://.",
    ),
    (
        "intercept.watching",
        "Interception ist kein Beobachten. Alles andere, was Flowlight tut, liest, was eine Anwendung ihrer \
         TLS-Bibliothek übergibt, und ändert nichts an dem, was über das Netzwerk geht.",
    ),
    (
        "intercept.agents.none",
        "Es sind keine Agenten genannt, also wird nichts umgeleitet. Interception gilt für die Agenten, die \
         sie nennt, und für nichts anderes auf diesem Rechner.",
    ),
    (
        "intercept.agents",
        "Verbindungen von {agents} – und von allem, was diese starten – werden auf einen Proxy auf diesem \
         Rechner umgeleitet, der TLS beendet und selbst eine Verbindung nach außen aufbaut.",
    ),
    (
        "intercept.authority",
        "Dieser Proxy zeigt ein Zertifikat, das von einer auf diesem Rechner erzeugten Zertifizierungsstelle \
         signiert ist. Alles, was ihr nicht vertraut, verweigert die Verbindung – und genau das soll ein \
         angepinntes Zertifikat tun.",
    ),
    (
        "intercept.passthrough",
        "Ein Host, für den niemand einen Mock geschrieben hat, wird durchgelassen und gar nicht beendet; das \
         Zertifikat wird also nur dort gezeigt, wo es einen Grund dafür gibt.",
    ),
    (
        "intercept.never",
        "Diese werden niemals beendet, was auch sonst gesagt wird: {hosts}.",
    ),
    (
        "intercept.off",
        "Ausschalten beendet die Umleitung sofort. Die Zertifizierungsstelle zu entfernen ist ein eigener \
         Schritt, denn ihr zu vertrauen und ihr das Vertrauen zu entziehen sind beides Dinge, die jemand \
         absichtlich tun sollte.",
    ),
    (
        "owners.what",
        "Flowlight wird fragen, wer die Adressen betreibt, mit denen sich dieser Rechner verbunden hat.",
    ),
    (
        "owners.question",
        "Die Frage ist eine DNS-Abfrage der öffentlichen Routing-Daten von Team Cymru, gesendet an {resolver} \
         – den eigenen Resolver dieses Rechners oder einen öffentlichen, falls keiner eingerichtet ist.",
    ),
    (
        "owners.sent",
        "Gesendet wird eine Adresse. Nicht, welcher Prozess sie erreicht hat, nicht wann, nicht wie oft und \
         nichts anderes, was Flowlight darüber weiß.",
    ),
    (
        "owners.local",
        "Nach einer Adresse auf diesem Rechner oder in diesem Netzwerk wird niemals gefragt: die Antwort ist \
         bereits bekannt, und die Frage wäre eine Frage über Ihr Netzwerk.",
    ),
    (
        "owners.rate",
        "Höchstens vier Adressen pro Minute, die verkehrsreichsten zuerst, und niemals dieselbe zweimal.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask ist ausgeschaltet. Flowlight für Linux hat kein Modell, also muss eines eingerichtet werden: `flowlightd model --kind local --model <name>` für einen Server auf diesem Rechner, oder ein Anbieter und ein Schlüssel.",
    ),
    (
        "ask.why.no_endpoint",
        "Es ist kein Endpunkt gesetzt, also gibt es nichts zu fragen.",
    ),
    (
        "ask.why.no_model",
        "Es ist kein Modellname gesetzt. Jedem Anbieter muss gesagt werden, welches Modell zu verwenden ist, und es gibt keine sinnvolle Vorgabe zum Raten.",
    ),
    (
        "ask.why.no_key",
        "{kind} braucht einen Schlüssel, und es liegt keiner vor.",
    ),
    ("ask.why.unconfigured", "Ask ist nicht eingerichtet."),
    (
        "intercept.why.off",
        "Interception ist ausgeschaltet. Es wird nichts beendet, und kein Zertifikat von Flowlight wird irgendetwas vorgelegt.",
    ),
    (
        "intercept.why.no_agents",
        "Interception ist eingeschaltet und nennt keine Agenten, also wird nichts umgeleitet. Einen zu nennen ist die Art, den Geltungsbereich zu wählen: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "einen öffentlichen Resolver"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "Nutzdaten werden überhaupt nicht gelesen. Verbindungen werden weiterhin zugeordnet.",
    ),
    (
        "budget.session.expired",
        "Die Erfassung von Nutzdaten ist abgelaufen und liest nichts mehr. Erneuern Sie sie, um wieder zu beginnen.",
    ),
    (
        "budget.session.remaining",
        "Nutzdaten werden noch {remaining} gelesen.",
    ),
    (
        "budget.session.unlimited",
        "Nutzdaten werden gelesen, ohne Sitzungsbegrenzung – was ausdrücklich verlangt und nicht angenommen wurde.",
    ),
    (
        "budget.daily.none",
        "Es gibt keine Tagesobergrenze dafür, wie viel ein einzelner Prozess beitragen darf.",
    ),
    (
        "budget.daily",
        "Nach {size} an einem Tag werden von einem Prozess bis zum nächsten Tag keine Nutzdaten mehr erfasst.",
    ),
    (
        "budget.paths.full",
        "Anfragepfade werden vollständig aufbewahrt, ohne die darin enthaltenen Zugangsdaten.",
    ),
    (
        "budget.paths.host",
        "Es wird nur der Host einer Anfrage aufbewahrt, niemals der Pfad, den sie angefragt hat.",
    ),
    (
        "budget.paths.none",
        "Weder Pfade noch Query-Strings werden aufbewahrt. Hosts schon, weil sich ohne sie nichts gruppieren lässt.",
    ),
    (
        "budget.retention",
        "Einzelne Anfragen werden {detail} aufbewahrt, eine Tageszusammenfassung {summary}.",
    ),
    ("time.seconds.one", "{count} Sekunde"),
    ("time.seconds.many", "{count} Sekunden"),
    ("time.minutes.one", "{count} Minute"),
    ("time.minutes.many", "{count} Minuten"),
    ("time.hours.one", "{count} Stunde"),
    ("time.hours.many", "{count} Stunden"),
    ("time.joined", "{hours} und {minutes}"),
    ("size.bytes", "{count} Bytes"),
    // The channels that are not the network.
    (
        "devices.channels",
        "Das sind die Kanäle, die nicht das Netzwerk sind: was über USB angeschlossen ist, was über Bluetooth gekoppelt ist und welche entfernbaren Datenträger eingebunden sind.",
    ),
    (
        "devices.no_bytes",
        "Berichtet wird, was angeschlossen ist und wann sich das geändert hat. Niemals, wie viel darüber gegangen ist: Linux rechnet Bytes nicht so pro Gerät ab, dass sie einem Prozess zugeordnet werden könnten, und eine Zahl, für die niemand einstehen kann, ist schlechter als keine Zahl.",
    ),
    (
        "devices.sources",
        "Alles wird aus den Dateien gelesen, die der Kernel in /sys und /proc bereits veröffentlicht. Kein Systemdienst wird gefragt, und nichts verlässt diesen Rechner.",
    ),
    (
        "devices.off",
        "Ausgeschaltet, bis es verlangt wird – nicht weil eine Berechtigung fehlt, sondern weil es erweitert, was beobachtet wird.",
    ),
];
