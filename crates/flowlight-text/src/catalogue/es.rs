//! Español. Una traducción del original en inglés, todavía sin revisión de un hablante nativo.

/// Cada frase, en el orden en que aparece en pantalla.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "Este texto es una traducción y todavía no lo ha revisado un hablante nativo. Flowlight se prueba \
         contra la redacción en inglés; donde las dos difieran, la inglesa es lo que hace el programa.",
    ),
    ("days.one", "{count} día"),
    ("days.many", "{count} días"),
    (
        "retention.describe",
        "las peticiones individuales se guardan {detail}, y un resumen diario {summary}",
    ),
    ("field.at", "cuándo"),
    ("field.process", "el proceso"),
    ("field.confidence", "cómo se nombró el proceso"),
    ("field.pid", "el identificador del proceso"),
    ("field.agent", "el agente"),
    ("field.direction", "la dirección del tráfico"),
    ("field.host", "el host"),
    ("field.method", "el método"),
    ("field.target", "la ruta"),
    ("field.status", "el estado"),
    ("field.bytes", "el tamaño"),
    ("field.protocol", "el protocolo"),
    ("field.rpc_method", "el método MCP"),
    ("field.rpc_tool", "el nombre de la herramienta"),
    (
        "export.destination.none",
        "No se ha fijado ningún destino, así que no puede enviarse nada a ninguna parte.",
    ),
    (
        "export.destination.otlp",
        "Cada petición que Flowlight lea se enviará por la red a {destination}, como OTLP.",
    ),
    (
        "export.destination.file",
        "Cada petición que Flowlight lea se escribirá en {destination}, una línea por petición. Nada cruza la \
         red.",
    ),
    (
        "export.destination.unusable",
        "{destination} no es ni un collector ni una ruta de archivo absoluta, así que no puede enviarse nada \
         allí.",
    ),
    (
        "export.fields.none",
        "No viaja ningún campo, lo que significa que cada registro no diría absolutamente nada.",
    ),
    ("export.fields.one", "Viaja {count} campo: {fields}."),
    ("export.fields.many", "Viajan {count} campos: {fields}."),
    ("export.withheld", "Estos no: {fields}."),
    (
        "export.headers.one",
        "Se envía {count} cabecera con cada lote: {names}. Los valores no se muestran aquí y no forman parte de \
         aquello a lo que usted accede.",
    ),
    (
        "export.headers.many",
        "Se envían {count} cabeceras con cada lote: {names}. Los valores no se muestran aquí y no forman parte \
         de aquello a lo que usted accede.",
    ),
    (
        "export.bound",
        "Este consentimiento se refiere exactamente a eso. Cambiar el destino, los campos o las cabeceras \
         detiene la exportación hasta que alguien acceda de nuevo.",
    ),
    ("export.why.off", "La exportación está desactivada."),
    (
        "export.why.nowhere",
        "No se ha fijado ningún destino, así que no hay adónde enviar nada.",
    ),
    (
        "export.why.unusable",
        "El destino no es ni un collector http:// o https:// ni una ruta de archivo absoluta, así que no está \
         claro qué significaría enviar algo allí.",
    ),
    (
        "export.why.unagreed",
        "Nadie ha accedido a esto todavía. No se envía nada hasta que alguien lo haga.",
    ),
    (
        "export.why.changed",
        "Lo que se envía, o adónde, ha cambiado desde que alguien accedió. No se envía nada hasta que alguien \
         acceda a lo que es ahora.",
    ),
    (
        "ask.none",
        "No hay ningún modelo configurado, así que no se pueden responder preguntas. Flowlight para Linux no \
         tiene modelo propio: no incluye pesos ni apunta por omisión a la API de nadie.",
    ),
    (
        "ask.remote",
        "Su pregunta y los resultados de las consultas que Flowlight ejecute para ella se enviarán a \
         {endpoint}.",
    ),
    (
        "ask.local",
        "Su pregunta va a {endpoint}, que está en esta máquina o en esta red. Nada cruza internet.",
    ),
    (
        "ask.sent",
        "Se envían la pregunta, las instrucciones y los totales y nombres que devuelven las propias consultas \
         de Flowlight. Nunca una fila del historial, nunca la ruta de una petición y nunca nada que el modelo \
         no haya pedido.",
    ),
    (
        "ask.queries",
        "El modelo no ve la base de datos. Puede nombrar una consulta de una lista fija, que Flowlight \
         ejecuta; no hay lenguaje de consulta ni manera de escribir uno.",
    ),
    (
        "ask.recorded",
        "La conexión con el proveedor se registra y se atribuye a flowlightd, como la de cualquier otro \
         proceso. Una herramienta que ocultara su propio tráfico no tendría por qué mostrar el de nadie más.",
    ),
    (
        "ask.kind.local",
        "un servidor de modelos en esta máquina o en esta red",
    ),
    ("ask.kind.compatible", "un endpoint compatible con OpenAI"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} está bien."),
    ("ask.safety.not_a_url", "{endpoint} no es una URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} no es una dirección http:// ni https://.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} es http:// sin cifrar hacia una dirección que no es esta máquina ni una red privada. Una \
         clave y una pregunta sobre el tráfico de esta máquina cruzarían la red en claro, así que Flowlight no \
         las envía. Use https://.",
    ),
    (
        "intercept.watching",
        "La interceptación no es observar. Todo lo demás que hace Flowlight lee lo que una aplicación entrega a \
         su biblioteca TLS y no cambia nada de lo que cruza la red.",
    ),
    (
        "intercept.agents.none",
        "No se nombra ningún agente, así que no se redirige nada. La interceptación se aplica a los agentes que \
         nombra y a nada más en esta máquina.",
    ),
    (
        "intercept.agents",
        "Las conexiones de {agents} —y de todo lo que estos inicien— se redirigen a un proxy en esta máquina, \
         que termina TLS y abre su propia conexión hacia fuera.",
    ),
    (
        "intercept.authority",
        "Ese proxy presenta un certificado firmado por una autoridad de certificación creada en esta máquina. \
         Todo lo que no confíe en ella rechazará la conexión, que es lo que un certificado fijado debe hacer.",
    ),
    (
        "intercept.passthrough",
        "Un host para el que nadie ha escrito un mock pasa sin terminarse en absoluto, así que el certificado \
         solo se presenta donde hay una razón para ello.",
    ),
    (
        "intercept.never",
        "Estos nunca se terminan, diga lo que diga el resto: {hosts}.",
    ),
    (
        "intercept.off",
        "Desactivarla detiene la redirección de inmediato. Quitar la autoridad de certificación es un paso \
         aparte, porque confiar en una y retirarle la confianza son dos cosas que alguien debería hacer a \
         propósito.",
    ),
    (
        "owners.what",
        "Flowlight preguntará quién opera las direcciones a las que se ha conectado esta máquina.",
    ),
    (
        "owners.question",
        "La pregunta es una consulta DNS de los datos públicos de enrutamiento de Team Cymru, enviada a \
         {resolver}: el propio resolutor de esta máquina, o uno público si no tiene ninguno configurado.",
    ),
    (
        "owners.sent",
        "Lo que se envía es una dirección. No qué proceso la alcanzó, ni cuándo, ni con qué frecuencia, ni \
         nada más que Flowlight sepa de ella.",
    ),
    (
        "owners.local",
        "Nunca se pregunta por una dirección de esta máquina o de esta red: la respuesta ya se conoce, y la \
         pregunta sería sobre su red.",
    ),
    (
        "owners.rate",
        "Como máximo cuatro direcciones por minuto, las de más tráfico primero, y nunca la misma dos veces.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask está desactivado. Flowlight para Linux no tiene modelo, así que hay que configurar uno: `flowlightd model --kind local --model <name>` para un servidor en esta máquina, o un proveedor y una clave.",
    ),
    (
        "ask.why.no_endpoint",
        "No hay ningún endpoint fijado, así que no hay nada a lo que preguntar.",
    ),
    (
        "ask.why.no_model",
        "No hay ningún nombre de modelo fijado. A cada proveedor hay que decirle qué modelo usar, y no hay un valor por omisión razonable que adivinar.",
    ),
    (
        "ask.why.no_key",
        "{kind} necesita una clave, y no hay ninguna guardada.",
    ),
    ("ask.why.unconfigured", "Ask no está configurado."),
    (
        "intercept.why.off",
        "La interceptación está desactivada. No se termina nada, y no se presenta a nada ningún certificado de Flowlight.",
    ),
    (
        "intercept.why.no_agents",
        "La interceptación está activada y no nombra ningún agente, así que no se redirige nada. Nombrar uno es la manera de elegir el alcance: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "un resolutor público"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "Los contenidos no se leen en absoluto. Las conexiones se siguen atribuyendo.",
    ),
    (
        "budget.session.expired",
        "La captura de contenidos se ha agotado y ya no lee nada. Renuévela para empezar de nuevo.",
    ),
    (
        "budget.session.remaining",
        "Los contenidos se leerán durante {remaining} más.",
    ),
    (
        "budget.session.unlimited",
        "Los contenidos se están leyendo, sin límite de sesión, porque así se pidió y no porque se supusiera.",
    ),
    (
        "budget.daily.none",
        "No hay tope diario sobre cuánto puede aportar un solo proceso.",
    ),
    (
        "budget.daily",
        "Pasados {size} en un día, a un proceso deja de capturársele el contenido hasta mañana.",
    ),
    (
        "budget.paths.full",
        "Las rutas de las peticiones se guardan completas, con las credenciales quitadas.",
    ),
    (
        "budget.paths.host",
        "Solo se guarda el host de una petición, nunca la ruta que pidió.",
    ),
    (
        "budget.paths.none",
        "No se guardan ni rutas ni cadenas de consulta. Los hosts sí, porque sin ellos nada puede agruparse.",
    ),
    (
        "budget.retention",
        "Las peticiones individuales se guardan {detail}, y un resumen diario {summary}.",
    ),
    ("time.seconds.one", "{count} segundo"),
    ("time.seconds.many", "{count} segundos"),
    ("time.minutes.one", "{count} minuto"),
    ("time.minutes.many", "{count} minutos"),
    ("time.hours.one", "{count} hora"),
    ("time.hours.many", "{count} horas"),
    ("time.joined", "{hours} y {minutes}"),
    ("size.bytes", "{count} bytes"),
    // The channels that are not the network.
    (
        "devices.channels",
        "Estos son los canales que no son la red: lo que está conectado por USB, lo que está emparejado por Bluetooth y qué volúmenes extraíbles están montados.",
    ),
    (
        "devices.no_bytes",
        "Se informa de qué está conectado y de cuándo eso cambió. Nunca de cuánto pasó por ello: Linux no contabiliza bytes por dispositivo de ninguna manera que pueda atribuirse a un proceso, y una cifra que nadie puede sostener es peor que ninguna cifra.",
    ),
    (
        "devices.sources",
        "Todo se lee de los archivos que el núcleo ya publica en /sys y /proc. No se pregunta a ningún servicio del sistema, y nada sale de esta máquina.",
    ),
    (
        "devices.off",
        "Desactivado hasta que se pida: no porque falte un permiso, sino porque amplía lo que se observa.",
    ),
];
