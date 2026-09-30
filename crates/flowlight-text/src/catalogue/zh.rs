//! 简体中文。译自英文原文，尚未经母语者校读。

/// 全部句子，按其在界面上出现的顺序排列。
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "本文是译文，尚未经母语者校读。Flowlight 的测试以英文表述为准；两者不一致时，\
         程序实际的行为由英文表述决定。",
    ),
    ("days.one", "{count} 天"),
    ("days.many", "{count} 天"),
    (
        "retention.describe",
        "单条请求保留 {detail}，每日汇总保留 {summary}",
    ),
    ("field.at", "时间"),
    ("field.process", "进程"),
    ("field.confidence", "进程名的判定方式"),
    ("field.pid", "进程标识符"),
    ("field.agent", "代理程序"),
    ("field.direction", "流量方向"),
    ("field.host", "主机"),
    ("field.method", "方法"),
    ("field.target", "路径"),
    ("field.status", "状态"),
    ("field.bytes", "大小"),
    ("field.protocol", "协议"),
    ("field.rpc_method", "MCP 方法"),
    ("field.rpc_tool", "工具名称"),
    (
        "export.destination.none",
        "尚未设置目的地，因此不会向任何地方发送任何内容。",
    ),
    (
        "export.destination.otlp",
        "Flowlight 读取到的每一条请求都会以 OTLP 形式经网络发送至 {destination}。",
    ),
    (
        "export.destination.file",
        "Flowlight 读取到的每一条请求都会写入 {destination}，每条一行。不会有任何内容经过网络。",
    ),
    (
        "export.destination.unusable",
        "{destination} 既不是 collector，也不是绝对文件路径，因此无法向其发送任何内容。",
    ),
    (
        "export.fields.none",
        "没有任何字段被发送，也就是说每条记录什么都说明不了。",
    ),
    ("export.fields.one", "有 {count} 个字段被发送：{fields}。"),
    ("export.fields.many", "有 {count} 个字段被发送：{fields}。"),
    ("export.withheld", "以下字段不发送：{fields}。"),
    (
        "export.headers.one",
        "每批数据会附带 {count} 个标头：{names}。此处不显示其取值，取值也不在您同意的范围之内。",
    ),
    (
        "export.headers.many",
        "每批数据会附带 {count} 个标头：{names}。此处不显示其取值，取值也不在您同意的范围之内。",
    ),
    (
        "export.bound",
        "此项同意仅针对以上内容。一旦改动目的地、字段或标头，导出便会停止，直到有人重新同意。",
    ),
    ("export.why.off", "导出已关闭。"),
    (
        "export.why.nowhere",
        "尚未设置目的地，因此没有可发送的去处。",
    ),
    (
        "export.why.unusable",
        "目的地既不是 http:// 或 https:// 的 collector，也不是绝对文件路径，\
         因此无法确定向其发送意味着什么。",
    ),
    (
        "export.why.unagreed",
        "还没有人同意此项。在有人同意之前不会发送任何内容。",
    ),
    (
        "export.why.changed",
        "自有人同意以来，所发送的内容或发送的去处已经改变。在有人同意当前内容之前不会发送任何内容。",
    ),
    (
        "ask.none",
        "尚未配置模型，因此无法回答问题。Linux 版 Flowlight 没有自己的模型：\
         既不内置权重，也不会默认指向任何人的 API。",
    ),
    (
        "ask.remote",
        "您的问题，以及 Flowlight 为此执行的查询所得到的结果，都会发送至 {endpoint}。",
    ),
    (
        "ask.local",
        "您的问题会发往 {endpoint}，它位于本机或本网络内。不会有任何内容经过互联网。",
    ),
    (
        "ask.sent",
        "所发送的是问题、指令，以及 Flowlight 自身查询返回的汇总数值与名称。\
         绝不会发送历史记录中的某一行、请求的路径，也绝不会发送模型未曾索取的东西。",
    ),
    (
        "ask.queries",
        "模型看不到数据库。它只能从一份固定的查询清单中指名一项，由 Flowlight 执行；\
         这里没有查询语言，也无从编写。",
    ),
    (
        "ask.recorded",
        "与服务方之间的连接同样会被记录，并归属到 flowlightd，与其他任何进程一样。\
         一个隐藏自身流量的工具，没有资格展示别人的流量。",
    ),
    ("ask.kind.local", "本机或本网络内的模型服务"),
    ("ask.kind.compatible", "与 OpenAI 兼容的接口"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} 可以使用。"),
    ("ask.safety.not_a_url", "{endpoint} 不是一个 URL。"),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} 既不是 http:// 地址，也不是 https:// 地址。",
    ),
    (
        "ask.safety.clear",
        "{endpoint} 是指向非本机、也非私有网络地址的明文 http://。密钥，以及关于本机自身流量的问题，\
         都会以明文经过网络，因此 Flowlight 不会发送它们。请改用 https://。",
    ),
    (
        "intercept.watching",
        "拦截不是观察。Flowlight 做的其他一切，都只是读取应用程序交给其 TLS 库的内容，\
         不改动任何经过网络的东西。",
    ),
    (
        "intercept.agents.none",
        "没有指定任何代理程序，因此不会重定向任何连接。拦截只作用于它所指定的代理程序，\
         不作用于本机上的其他任何程序。",
    ),
    (
        "intercept.agents",
        "来自 {agents} 的连接——以及它们所启动的一切的连接——会被重定向到本机上的一个代理服务，\
         由后者终止 TLS 并自行向外建立连接。",
    ),
    (
        "intercept.authority",
        "该代理服务出示的证书，由本机上创建的证书颁发机构签发。不信任它的一方会拒绝连接，\
         而这正是证书固定本该发挥的作用。",
    ),
    (
        "intercept.passthrough",
        "对于没有人为其编写模拟响应的主机，连接会被直接放行、完全不做终止，\
         因此证书只会在确有理由的地方出示。",
    ),
    (
        "intercept.never",
        "无论其他设置如何，以下主机的连接绝不会被终止：{hosts}。",
    ),
    (
        "intercept.off",
        "关闭它会立即停止重定向。移除证书颁发机构是另一个步骤，\
         因为信任一个机构和撤回这份信任，都应当是有人有意去做的事。",
    ),
    (
        "owners.what",
        "Flowlight 将查询本机连接过的那些地址由谁运营。",
    ),
    (
        "owners.question",
        "查询的方式是向 {resolver} 发起一次 DNS 请求，读取 Team Cymru 的公开路由数据；\
         该解析器是本机自己配置的解析器，若未配置则为一个公共解析器。",
    ),
    (
        "owners.sent",
        "发送出去的只是一个地址。不包括是哪个进程连到它、在什么时候、连了多少次，\
         也不包括 Flowlight 知道的其他任何信息。",
    ),
    (
        "owners.local",
        "本机或本网络内的地址绝不会被查询：答案本就已知，而这样的查询问的是您的网络。",
    ),
    (
        "owners.rate",
        "每分钟最多四个地址，流量大的在前，同一个地址绝不查询两次。",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask 已关闭。Linux 版 Flowlight 没有模型，因此需要先配置一个：本机上的模型服务可用 `flowlightd model --kind local --model <name>`，或者配置一个服务方和密钥。",
    ),
    (
        "ask.why.no_endpoint",
        "尚未设置接口地址，因此没有可询问的对象。",
    ),
    (
        "ask.why.no_model",
        "尚未设置模型名称。每个服务方都需要被告知使用哪个模型，没有可以猜测的合理默认值。",
    ),
    (
        "ask.why.no_key",
        "{kind} 需要密钥，但本机没有保存任何密钥。",
    ),
    ("ask.why.unconfigured", "Ask 尚未配置。"),
    (
        "intercept.why.off",
        "拦截已关闭。不会终止任何连接，也不会向任何一方出示 Flowlight 的证书。",
    ),
    (
        "intercept.why.no_agents",
        "拦截已开启，但没有指定任何代理程序，因此不会重定向任何连接。指定代理程序就是选定作用范围的方式：`flowlightd intercept --agent claude`。",
    ),
    ("owners.resolver.public", "一个公共解析器"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "完全不读取报文内容。连接仍会被归属到进程。",
    ),
    (
        "budget.session.expired",
        "报文内容的采集时段已用尽，现在不再读取任何内容。续期后可重新开始。",
    ),
    (
        "budget.session.remaining",
        "报文内容还会再读取 {remaining}。",
    ),
    (
        "budget.session.unlimited",
        "正在读取报文内容，且没有时段上限——这是明确要求的设置，而非默认假定。",
    ),
    (
        "budget.daily.none",
        "对单个进程每天可贡献的数据量没有上限。",
    ),
    (
        "budget.daily",
        "一天之内超过 {size} 后，该进程的报文内容采集会暂停到第二天。",
    ),
    (
        "budget.paths.full",
        "请求路径会完整保留，其中的凭据会被去除。",
    ),
    (
        "budget.paths.host",
        "只保留请求的主机，绝不保留其请求的路径。",
    ),
    (
        "budget.paths.none",
        "路径和查询字符串都不保留。主机会保留，因为没有主机就无法做任何归类。",
    ),
    (
        "budget.retention",
        "单条请求保留 {detail}，每日汇总保留 {summary}。",
    ),
    ("time.seconds.one", "{count} 秒"),
    ("time.seconds.many", "{count} 秒"),
    ("time.minutes.one", "{count} 分钟"),
    ("time.minutes.many", "{count} 分钟"),
    ("time.hours.one", "{count} 小时"),
    ("time.hours.many", "{count} 小时"),
    ("time.joined", "{hours}{minutes}"),
    ("size.bytes", "{count} 字节"),
    // The channels that are not the network.
    (
        "devices.channels",
        "这些是网络之外的通道：通过 USB 接入的设备、通过蓝牙配对的设备，以及已挂载的可移动卷。",
    ),
    (
        "devices.no_bytes",
        "所报告的是什么设备处于连接状态，以及连接状态何时发生变化。绝不报告经由这些通道传输了多少数据：Linux 并不以可归属到进程的方式统计每台设备的字节数，而一个无人能为之负责的数字比没有数字更糟。",
    ),
    (
        "devices.sources",
        "所有信息都读自内核已经在 /sys 和 /proc 中公开的文件。不向任何系统服务发起询问，也不会有任何信息离开本机。",
    ),
    (
        "devices.off",
        "在被明确开启之前保持关闭——不是因为缺少权限，而是因为它会扩大所观察的范围。",
    ),
];
