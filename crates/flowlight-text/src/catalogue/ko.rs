//! 한국어. 영어 원문을 옮긴 것으로, 아직 원어민의 확인을 받지 않았습니다.

/// 화면에 나타나는 순서대로 정리한 모든 문장.
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "이 글은 번역이며 아직 원어민의 확인을 받지 않았습니다. Flowlight는 영어 문장을 기준으로 \
         시험됩니다. 둘이 다를 경우 프로그램이 실제로 하는 일을 나타내는 것은 영어 쪽입니다.",
    ),
    ("days.one", "{count}일"),
    ("days.many", "{count}일"),
    (
        "retention.describe",
        "개별 요청은 {detail}, 일별 요약은 {summary} 보관합니다",
    ),
    ("field.at", "시각"),
    ("field.process", "프로세스"),
    ("field.confidence", "프로세스 이름을 알아낸 방법"),
    ("field.pid", "프로세스 식별자"),
    ("field.agent", "에이전트"),
    ("field.direction", "통신 방향"),
    ("field.host", "호스트"),
    ("field.method", "메서드"),
    ("field.target", "경로"),
    ("field.status", "상태"),
    ("field.bytes", "크기"),
    ("field.protocol", "프로토콜"),
    ("field.rpc_method", "MCP 메서드"),
    ("field.rpc_tool", "도구 이름"),
    (
        "export.destination.none",
        "보낼 곳이 설정되지 않았으므로 어디로도 아무것도 보내지 않습니다.",
    ),
    (
        "export.destination.otlp",
        "Flowlight가 읽은 모든 요청이 OTLP로 네트워크를 통해 {destination}(으)로 전송됩니다.",
    ),
    (
        "export.destination.file",
        "Flowlight가 읽은 모든 요청이 한 줄씩 {destination}에 기록됩니다. 네트워크로 나가는 것은 \
         없습니다.",
    ),
    (
        "export.destination.unusable",
        "{destination}은(는) 수집기도 절대 경로도 아니므로 그곳으로는 아무것도 보낼 수 없습니다.",
    ),
    (
        "export.fields.none",
        "전송되는 항목이 없으므로 각 기록은 아무것도 말해 주지 않게 됩니다.",
    ),
    (
        "export.fields.one",
        "전송되는 항목은 {count}개입니다: {fields}.",
    ),
    (
        "export.fields.many",
        "전송되는 항목은 {count}개입니다: {fields}.",
    ),
    ("export.withheld", "전송되지 않는 항목: {fields}."),
    (
        "export.headers.one",
        "각 묶음과 함께 헤더 {count}개가 전송됩니다: {names}. 값은 여기에 표시되지 않으며 동의의 \
         대상에도 포함되지 않습니다.",
    ),
    (
        "export.headers.many",
        "각 묶음과 함께 헤더 {count}개가 전송됩니다: {names}. 값은 여기에 표시되지 않으며 동의의 \
         대상에도 포함되지 않습니다.",
    ),
    (
        "export.bound",
        "이 동의는 바로 그 내용에 대한 것입니다. 보낼 곳, 항목, 헤더 중 무엇이라도 바뀌면 누군가 다시 \
         동의할 때까지 내보내기가 멈춥니다.",
    ),
    ("export.why.off", "내보내기가 꺼져 있습니다."),
    (
        "export.why.nowhere",
        "보낼 곳이 설정되지 않았으므로 보낼 대상이 없습니다.",
    ),
    (
        "export.why.unusable",
        "보낼 곳이 http:// 또는 https:// 수집기도 절대 경로도 아니므로, 그곳으로 보낸다는 것이 무엇을 \
         뜻하는지 분명하지 않습니다.",
    ),
    (
        "export.why.unagreed",
        "아직 아무도 이에 동의하지 않았습니다. 누군가 동의할 때까지 아무것도 보내지 않습니다.",
    ),
    (
        "export.why.changed",
        "누군가 동의한 뒤로 무엇을 보내는지 또는 어디로 보내는지가 바뀌었습니다. 지금의 내용에 누군가 \
         동의할 때까지 아무것도 보내지 않습니다.",
    ),
    (
        "ask.none",
        "설정된 모델이 없으므로 질문에 답할 수 없습니다. Linux용 Flowlight에는 자체 모델이 없습니다. \
         가중치를 함께 담지 않으며, 기본값으로 누군가의 API를 가리키지도 않습니다.",
    ),
    (
        "ask.remote",
        "당신의 질문과, 그것을 위해 Flowlight가 실행한 조회 결과가 {endpoint}(으)로 전송됩니다.",
    ),
    (
        "ask.local",
        "당신의 질문은 이 기기 또는 이 네트워크에 있는 {endpoint}(으)로 갑니다. 인터넷으로 나가는 것은 \
         없습니다.",
    ),
    (
        "ask.sent",
        "전송되는 것은 질문, 지시문, 그리고 Flowlight 자신의 조회가 돌려주는 합계와 이름입니다. 기록의 \
         한 줄이나 요청 경로, 모델이 요청하지 않은 것은 결코 전송되지 않습니다.",
    ),
    (
        "ask.queries",
        "모델은 데이터베이스를 볼 수 없습니다. 정해진 목록에서 조회를 이름으로 고를 수 있고 그것을 \
         Flowlight가 실행합니다. 조회 언어는 없으며 새로 쓸 방법도 없습니다.",
    ),
    (
        "ask.recorded",
        "공급자로의 연결도 다른 프로세스와 마찬가지로 기록되어 flowlightd에 귀속됩니다. 자신의 통신을 \
         숨기는 도구가 남의 통신을 보여 줄 자격은 없습니다.",
    ),
    ("ask.kind.local", "이 기기 또는 이 네트워크의 모델 서버"),
    ("ask.kind.compatible", "OpenAI 호환 엔드포인트"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint}은(는) 문제없습니다."),
    ("ask.safety.not_a_url", "{endpoint}은(는) URL이 아닙니다."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint}은(는) http:// 주소도 https:// 주소도 아닙니다.",
    ),
    (
        "ask.safety.clear",
        "{endpoint}은(는) 이 기기도 사설 네트워크도 아닌 주소로 향하는 평문 http://입니다. 키와 이 기기 \
         자신의 통신에 관한 질문이 암호화되지 않은 채 네트워크를 지나게 되므로 Flowlight는 그것을 보내지 \
         않습니다. https://를 사용하십시오.",
    ),
    (
        "intercept.watching",
        "가로채기는 관찰이 아닙니다. Flowlight가 하는 그 밖의 모든 일은 응용 프로그램이 자신의 TLS \
         라이브러리에 넘기는 것을 읽을 뿐이며, 네트워크를 지나는 것은 무엇도 바꾸지 않습니다.",
    ),
    (
        "intercept.agents.none",
        "지정된 에이전트가 없으므로 아무것도 우회되지 않습니다. 가로채기는 이름이 적힌 에이전트에만 \
         적용되며 이 기기의 다른 것에는 적용되지 않습니다.",
    ),
    (
        "intercept.agents",
        "{agents}에서 나가는 연결과 그것들이 시작한 모든 것의 연결이 이 기기의 프록시로 우회됩니다. \
         프록시는 TLS를 종료하고 바깥으로 자신의 연결을 엽니다.",
    ),
    (
        "intercept.authority",
        "그 프록시는 이 기기에서 만든 인증 기관이 서명한 인증서를 제시합니다. 그것을 신뢰하지 않는 쪽은 \
         연결을 거부하며, 고정된 인증서란 바로 그렇게 동작해야 하는 것입니다.",
    ),
    (
        "intercept.passthrough",
        "아무도 모의 응답을 쓰지 않은 호스트는 종료되지 않고 그대로 지나가므로, 인증서는 그럴 이유가 \
         있는 곳에만 제시됩니다.",
    ),
    (
        "intercept.never",
        "다른 설정이 무엇이라 하더라도 다음 호스트는 결코 종료되지 않습니다: {hosts}.",
    ),
    (
        "intercept.off",
        "끄면 우회가 즉시 멈춥니다. 인증 기관을 제거하는 것은 별도의 단계입니다. 신뢰하는 것과 신뢰를 \
         거두는 것은 모두 의도해서 해야 하는 일이기 때문입니다.",
    ),
    (
        "owners.what",
        "Flowlight는 이 기기가 연결한 주소를 누가 운영하는지 조회합니다.",
    ),
    (
        "owners.question",
        "조회는 Team Cymru의 공개 경로 데이터에 대한 DNS 질의이며 {resolver}(으)로 보냅니다. 이는 이 \
         기기 자신의 리졸버이거나, 설정된 것이 없으면 공개 리졸버입니다.",
    ),
    (
        "owners.sent",
        "전송되는 것은 주소입니다. 어느 프로세스가 도달했는지, 언제, 몇 번인지, 그 밖에 Flowlight가 아는 \
         것은 보내지 않습니다.",
    ),
    (
        "owners.local",
        "이 기기나 이 네트워크의 주소는 결코 조회하지 않습니다. 답은 이미 알고 있으며, 그 질문은 당신의 \
         네트워크에 관한 질문이 되기 때문입니다.",
    ),
    (
        "owners.rate",
        "1분에 최대 네 개, 통신량이 많은 것부터, 같은 주소는 두 번 묻지 않습니다.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask가 꺼져 있습니다. Linux용 Flowlight에는 모델이 없으므로 하나를 설정해야 합니다. 이 기기의 서버라면 `flowlightd model --kind local --model <name>`, 아니면 공급자와 키를 설정하십시오.",
    ),
    (
        "ask.why.no_endpoint",
        "엔드포인트가 설정되지 않았으므로 물어볼 대상이 없습니다.",
    ),
    (
        "ask.why.no_model",
        "모델 이름이 설정되지 않았습니다. 모든 공급자에게는 어떤 모델을 쓸지 알려 주어야 하며, 짐작해도 되는 기본값은 없습니다.",
    ),
    (
        "ask.why.no_key",
        "{kind}에는 키가 필요하지만 저장된 키가 없습니다.",
    ),
    ("ask.why.unconfigured", "Ask가 설정되지 않았습니다."),
    (
        "intercept.why.off",
        "가로채기가 꺼져 있습니다. 아무것도 종료되지 않으며, Flowlight의 인증서가 어디에도 제시되지 않습니다.",
    ),
    (
        "intercept.why.no_agents",
        "가로채기는 켜져 있지만 지정된 에이전트가 없으므로 아무것도 우회되지 않습니다. 범위는 에이전트를 지정해 정합니다: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "공개 리졸버"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "페이로드는 전혀 읽지 않습니다. 연결의 귀속은 계속 이루어집니다.",
    ),
    (
        "budget.session.expired",
        "페이로드 수집 기간이 끝나 더 이상 아무것도 읽지 않습니다. 다시 시작하려면 기간을 갱신하십시오.",
    ),
    (
        "budget.session.remaining",
        "페이로드는 {remaining} 더 읽힙니다.",
    ),
    (
        "budget.session.unlimited",
        "페이로드를 세션 제한 없이 읽고 있습니다. 이는 요청된 설정이며 기본값이 아닙니다.",
    ),
    (
        "budget.daily.none",
        "한 프로세스가 하루에 기여할 수 있는 양에 상한이 없습니다.",
    ),
    (
        "budget.daily",
        "하루에 {size}을(를) 넘기면 그 프로세스의 페이로드 수집은 다음 날까지 멈춥니다.",
    ),
    (
        "budget.paths.full",
        "요청 경로는 담겨 있던 자격 증명을 제거한 뒤 그대로 보관합니다.",
    ),
    (
        "budget.paths.host",
        "요청의 호스트만 보관하며, 요청한 경로는 보관하지 않습니다.",
    ),
    (
        "budget.paths.none",
        "경로도 질의 문자열도 보관하지 않습니다. 호스트는 보관합니다. 호스트가 없으면 무엇도 묶어 볼 수 없기 때문입니다.",
    ),
    (
        "budget.retention",
        "개별 요청은 {detail}, 일별 요약은 {summary} 보관합니다.",
    ),
    ("time.seconds.one", "{count}초"),
    ("time.seconds.many", "{count}초"),
    ("time.minutes.one", "{count}분"),
    ("time.minutes.many", "{count}분"),
    ("time.hours.one", "{count}시간"),
    ("time.hours.many", "{count}시간"),
    ("time.joined", "{hours} {minutes}"),
    ("size.bytes", "{count}바이트"),
    // The channels that are not the network.
    (
        "devices.channels",
        "이것은 네트워크가 아닌 경로입니다. USB로 연결된 것, Bluetooth로 연결된 것, 그리고 마운트된 이동식 볼륨입니다.",
    ),
    (
        "devices.no_bytes",
        "보고하는 것은 무엇이 연결되어 있는지와 그것이 언제 바뀌었는지입니다. 그 경로로 얼마나 오갔는지는 결코 보고하지 않습니다. Linux는 프로세스에 귀속할 수 있는 방식으로 장치별 바이트를 집계하지 않으며, 아무도 책임질 수 없는 숫자는 숫자가 없는 것보다 나쁩니다.",
    ),
    (
        "devices.sources",
        "모든 것은 커널이 이미 /sys와 /proc에 공개하는 파일에서 읽습니다. 어떤 시스템 서비스에도 묻지 않으며, 이 기기를 떠나는 것은 없습니다.",
    ),
    (
        "devices.off",
        "요청할 때까지 꺼져 있습니다. 권한이 없어서가 아니라, 살펴보는 범위를 넓히는 일이기 때문입니다.",
    ),
];
