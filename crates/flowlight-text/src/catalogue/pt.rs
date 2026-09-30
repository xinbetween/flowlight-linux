//! Português. Uma tradução do original em inglês, ainda sem revisão de uma pessoa falante nativa.

/// Cada frase, na ordem em que aparece no ecrã.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "Este texto é uma tradução e ainda não foi revisto por uma pessoa falante nativa. O Flowlight é testado \
         contra a redação em inglês; onde as duas divergirem, é a inglesa que descreve o que o programa faz.",
    ),
    ("days.one", "{count} dia"),
    ("days.many", "{count} dias"),
    (
        "retention.describe",
        "os pedidos individuais são guardados {detail}, e um resumo diário {summary}",
    ),
    ("field.at", "quando"),
    ("field.process", "o processo"),
    ("field.confidence", "como o processo foi identificado"),
    ("field.pid", "o identificador do processo"),
    ("field.agent", "o agente"),
    ("field.direction", "o sentido do tráfego"),
    ("field.host", "o host"),
    ("field.method", "o método"),
    ("field.target", "o caminho"),
    ("field.status", "o estado"),
    ("field.bytes", "o tamanho"),
    ("field.protocol", "o protocolo"),
    ("field.rpc_method", "o método MCP"),
    ("field.rpc_tool", "o nome da ferramenta"),
    (
        "export.destination.none",
        "Não há destino definido, portanto nada pode ser enviado para lugar algum.",
    ),
    (
        "export.destination.otlp",
        "Cada pedido que o Flowlight ler será enviado pela rede para {destination}, em OTLP.",
    ),
    (
        "export.destination.file",
        "Cada pedido que o Flowlight ler será escrito em {destination}, uma linha por pedido. Nada atravessa a \
         rede.",
    ),
    (
        "export.destination.unusable",
        "{destination} não é um coletor nem um caminho de ficheiro absoluto, portanto nada pode ser enviado \
         para lá.",
    ),
    (
        "export.fields.none",
        "Nenhum campo viaja, o que significa que cada registo não diria nada.",
    ),
    ("export.fields.one", "Viaja {count} campo: {fields}."),
    ("export.fields.many", "Viajam {count} campos: {fields}."),
    ("export.withheld", "Estes não: {fields}."),
    (
        "export.headers.one",
        "É enviado {count} cabeçalho com cada lote: {names}. Os valores não são mostrados aqui e não fazem \
         parte daquilo com que está a concordar.",
    ),
    (
        "export.headers.many",
        "São enviados {count} cabeçalhos com cada lote: {names}. Os valores não são mostrados aqui e não fazem \
         parte daquilo com que está a concordar.",
    ),
    (
        "export.bound",
        "Este consentimento diz respeito exactamente a isso. Alterar o destino, os campos ou os cabeçalhos \
         interrompe a exportação até que alguém concorde de novo.",
    ),
    ("export.why.off", "A exportação está desligada."),
    (
        "export.why.nowhere",
        "Não há destino definido, portanto não há para onde enviar nada.",
    ),
    (
        "export.why.unusable",
        "O destino não é um coletor http:// ou https:// nem um caminho de ficheiro absoluto, portanto não é \
         claro o que significaria enviar algo para lá.",
    ),
    (
        "export.why.unagreed",
        "Ninguém concordou com isto ainda. Nada é enviado até que alguém concorde.",
    ),
    (
        "export.why.changed",
        "O que é enviado, ou para onde, mudou desde que alguém concordou. Nada é enviado até que alguém \
         concorde com o que é agora.",
    ),
    (
        "ask.none",
        "Não há nenhum modelo configurado, portanto não é possível responder a perguntas. O Flowlight para \
         Linux não tem modelo próprio: não inclui pesos nem aponta por omissão para a API de ninguém.",
    ),
    (
        "ask.remote",
        "A sua pergunta e os resultados das consultas que o Flowlight executa para ela serão enviados para \
         {endpoint}.",
    ),
    (
        "ask.local",
        "A sua pergunta vai para {endpoint}, que está nesta máquina ou nesta rede. Nada atravessa a internet.",
    ),
    (
        "ask.sent",
        "O que é enviado é a pergunta, as instruções e os totais e nomes que as próprias consultas do Flowlight \
         devolvem. Nunca uma linha do histórico, nunca o caminho de um pedido e nunca nada que o modelo não \
         tenha pedido.",
    ),
    (
        "ask.queries",
        "O modelo não vê a base de dados. Pode nomear uma consulta de uma lista fixa, que o Flowlight executa; \
         não há linguagem de consulta nem maneira de escrever uma.",
    ),
    (
        "ask.recorded",
        "A ligação ao fornecedor é registada e atribuída ao flowlightd, como a de qualquer outro processo. Uma \
         ferramenta que escondesse o seu próprio tráfego não teria razão para mostrar o de outros.",
    ),
    (
        "ask.kind.local",
        "um servidor de modelos nesta máquina ou nesta rede",
    ),
    ("ask.kind.compatible", "um endpoint compatível com a OpenAI"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} serve."),
    ("ask.safety.not_a_url", "{endpoint} não é um URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} não é um endereço http:// nem https://.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} é http:// em claro para um endereço que não é esta máquina nem uma rede privada. Uma chave \
         e uma pergunta sobre o tráfego desta máquina atravessariam a rede em claro, por isso o Flowlight não \
         as envia. Use https://.",
    ),
    (
        "intercept.watching",
        "Interceptar não é observar. Tudo o mais que o Flowlight faz lê o que uma aplicação entrega à sua \
         biblioteca TLS e não altera nada do que atravessa a rede.",
    ),
    (
        "intercept.agents.none",
        "Não há agentes indicados, portanto nada é redirecionado. A interceptação aplica-se aos agentes que \
         indica e a mais nada nesta máquina.",
    ),
    (
        "intercept.agents",
        "As ligações de {agents} — e de tudo o que estes iniciem — são redirecionadas para um proxy nesta \
         máquina, que termina o TLS e abre a sua própria ligação para o exterior.",
    ),
    (
        "intercept.authority",
        "Esse proxy apresenta um certificado assinado por uma autoridade de certificação criada nesta máquina. \
         Tudo o que não confie nela recusará a ligação, que é precisamente o que um certificado fixado deve \
         fazer.",
    ),
    (
        "intercept.passthrough",
        "Um host para o qual ninguém escreveu uma resposta simulada passa sem ser terminado, pelo que o \
         certificado só é apresentado onde há razão para isso.",
    ),
    (
        "intercept.never",
        "Estes nunca são terminados, diga o resto o que disser: {hosts}.",
    ),
    (
        "intercept.off",
        "Desligá-la interrompe o redirecionamento de imediato. Remover a autoridade de certificação é um passo \
         separado, porque confiar numa e retirar-lhe a confiança são ambas coisas que alguém deve fazer de \
         propósito.",
    ),
    (
        "owners.what",
        "O Flowlight vai perguntar quem opera os endereços a que esta máquina se ligou.",
    ),
    (
        "owners.question",
        "A pergunta é uma consulta DNS aos dados públicos de encaminhamento da Team Cymru, enviada para \
         {resolver} — o resolvedor desta máquina, ou um público se não tiver nenhum configurado.",
    ),
    (
        "owners.sent",
        "O que é enviado é um endereço. Não qual processo o alcançou, nem quando, nem com que frequência, nem \
         mais nada que o Flowlight saiba sobre ele.",
    ),
    (
        "owners.local",
        "Um endereço desta máquina ou desta rede nunca é consultado: a resposta já é conhecida, e a pergunta \
         seria sobre a sua rede.",
    ),
    (
        "owners.rate",
        "No máximo quatro endereços por minuto, os de maior tráfego primeiro, e nunca o mesmo duas vezes.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "O Ask está desligado. O Flowlight para Linux não tem modelo, por isso é preciso configurar um: `flowlightd model --kind local --model <name>` para um servidor nesta máquina, ou um fornecedor e uma chave.",
    ),
    (
        "ask.why.no_endpoint",
        "Não há endpoint definido, portanto não há nada a que perguntar.",
    ),
    (
        "ask.why.no_model",
        "Não há nome de modelo definido. A cada fornecedor é preciso dizer que modelo usar, e não há um valor por omissão razoável que se possa adivinhar.",
    ),
    (
        "ask.why.no_key",
        "{kind} precisa de uma chave, e não há nenhuma guardada.",
    ),
    ("ask.why.unconfigured", "O Ask não está configurado."),
    (
        "intercept.why.off",
        "A interceptação está desligada. Nada é terminado, e nenhum certificado do Flowlight é apresentado a nada.",
    ),
    (
        "intercept.why.no_agents",
        "A interceptação está ligada e não indica agentes, portanto nada é redirecionado. Indicar um é a forma de escolher o âmbito: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "um resolvedor público"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "Os conteúdos não são lidos de forma alguma. As ligações continuam a ser atribuídas.",
    ),
    (
        "budget.session.expired",
        "A captura de conteúdos esgotou-se e já não lê nada. Renove-a para começar de novo.",
    ),
    (
        "budget.session.remaining",
        "Os conteúdos serão lidos durante mais {remaining}.",
    ),
    (
        "budget.session.unlimited",
        "Os conteúdos estão a ser lidos, sem limite de sessão — o que foi pedido, não presumido.",
    ),
    (
        "budget.daily.none",
        "Não há limite diário para quanto um único processo pode contribuir.",
    ),
    (
        "budget.daily",
        "Passados {size} num dia, os conteúdos de um processo deixam de ser capturados até ao dia seguinte.",
    ),
    (
        "budget.paths.full",
        "Os caminhos dos pedidos são guardados na íntegra, com as credenciais removidas.",
    ),
    (
        "budget.paths.host",
        "Só o host de um pedido é guardado, nunca o caminho que pediu.",
    ),
    (
        "budget.paths.none",
        "Nem caminhos nem cadeias de consulta são guardados. Os hosts são, porque sem eles nada pode ser agrupado.",
    ),
    (
        "budget.retention",
        "Os pedidos individuais são guardados {detail}, e um resumo diário {summary}.",
    ),
    ("time.seconds.one", "{count} segundo"),
    ("time.seconds.many", "{count} segundos"),
    ("time.minutes.one", "{count} minuto"),
    ("time.minutes.many", "{count} minutos"),
    ("time.hours.one", "{count} hora"),
    ("time.hours.many", "{count} horas"),
    ("time.joined", "{hours} e {minutes}"),
    ("size.bytes", "{count} bytes"),
    // The channels that are not the network.
    (
        "devices.channels",
        "Estes são os canais que não são a rede: o que está ligado por USB, o que está emparelhado por Bluetooth e quais volumes removíveis estão montados.",
    ),
    (
        "devices.no_bytes",
        "O que é comunicado é o que está ligado e quando isso mudou. Nunca quanto passou por ali: o Linux não contabiliza bytes por dispositivo de uma forma que possa ser atribuída a um processo, e um número que ninguém pode defender é pior do que número nenhum.",
    ),
    (
        "devices.sources",
        "Tudo é lido dos ficheiros que o núcleo já publica em /sys e /proc. Nenhum serviço do sistema é consultado, e nada sai desta máquina.",
    ),
    (
        "devices.off",
        "Desligado até que seja pedido — não por falta de uma permissão, mas porque alarga aquilo que é observado.",
    ),
];
