//! 日本語。英語の原文からの翻訳で、母語話者による確認はまだ受けていません。

/// 画面に現れる順に並べた、すべての文。
pub const PHRASES: &[(&str, &str)] = &[
    (
        "text.translated",
        "この文章は翻訳であり、母語話者による確認はまだ受けていません。Flowlight は英語の表現に対して\
         テストされています。両者が食い違う場合、プログラムの実際の動作を表すのは英語のほうです。",
    ),
    ("days.one", "{count}日"),
    ("days.many", "{count}日"),
    (
        "retention.describe",
        "個々のリクエストは{detail}、日次の要約は{summary}保持されます",
    ),
    ("field.at", "時刻"),
    ("field.process", "プロセス"),
    ("field.confidence", "プロセス名の判定のしかた"),
    ("field.pid", "プロセス識別子"),
    ("field.agent", "エージェント"),
    ("field.direction", "通信の向き"),
    ("field.host", "ホスト"),
    ("field.method", "メソッド"),
    ("field.target", "パス"),
    ("field.status", "ステータス"),
    ("field.bytes", "サイズ"),
    ("field.protocol", "プロトコル"),
    ("field.rpc_method", "MCP のメソッド"),
    ("field.rpc_tool", "ツールの名前"),
    (
        "export.destination.none",
        "送信先が設定されていないため、どこにも何も送信されません。",
    ),
    (
        "export.destination.otlp",
        "Flowlight が読み取ったすべてのリクエストが、OTLP としてネットワーク経由で {destination} に送信されます。",
    ),
    (
        "export.destination.file",
        "Flowlight が読み取ったすべてのリクエストが、1 行ずつ {destination} に書き出されます。\
         ネットワークには何も出ていきません。",
    ),
    (
        "export.destination.unusable",
        "{destination} はコレクターでも絶対パスでもないため、そこには何も送信できません。",
    ),
    (
        "export.fields.none",
        "送信されるフィールドがないため、どのレコードも何も語らないことになります。",
    ),
    (
        "export.fields.one",
        "送信されるフィールドは{count}件です: {fields}。",
    ),
    (
        "export.fields.many",
        "送信されるフィールドは{count}件です: {fields}。",
    ),
    ("export.withheld", "送信されないもの: {fields}。"),
    (
        "export.headers.one",
        "各バッチとともに{count}件のヘッダーが送信されます: {names}。値はここには表示されず、\
         同意の対象にも含まれません。",
    ),
    (
        "export.headers.many",
        "各バッチとともに{count}件のヘッダーが送信されます: {names}。値はここには表示されず、\
         同意の対象にも含まれません。",
    ),
    (
        "export.bound",
        "この同意は、ここに書かれている内容そのものに対するものです。送信先、フィールド、ヘッダーのいずれかを\
         変更すると、誰かが改めて同意するまでエクスポートは停止します。",
    ),
    ("export.why.off", "エクスポートは無効です。"),
    (
        "export.why.nowhere",
        "送信先が設定されていないため、送る先がありません。",
    ),
    (
        "export.why.unusable",
        "送信先が http:// または https:// のコレクターでも絶対パスでもないため、\
         そこへ送るとはどういうことなのかが決まりません。",
    ),
    (
        "export.why.unagreed",
        "まだ誰も同意していません。誰かが同意するまで何も送信されません。",
    ),
    (
        "export.why.changed",
        "誰かが同意した時点から、送信される内容または送信先が変わりました。現在の内容に誰かが同意するまで、\
         何も送信されません。",
    ),
    (
        "ask.none",
        "モデルが設定されていないため、質問に答えることはできません。Linux 版の Flowlight は自前のモデルを\
         持ちません。重みを同梱しておらず、既定で誰かの API を指すこともありません。",
    ),
    (
        "ask.remote",
        "あなたの質問と、そのために Flowlight が実行する問い合わせの結果が {endpoint} に送信されます。",
    ),
    (
        "ask.local",
        "あなたの質問は、このマシンまたはこのネットワーク上にある {endpoint} に送られます。\
         インターネットには何も出ていきません。",
    ),
    (
        "ask.sent",
        "送信されるのは、質問、指示、そして Flowlight 自身の問い合わせが返す合計値と名前です。\
         履歴の行そのものや、リクエストのパス、モデルが求めていないものは決して送信されません。",
    ),
    (
        "ask.queries",
        "モデルはデータベースを見ることはできません。決められた一覧の中から問い合わせを名前で指定でき、\
         それを Flowlight が実行します。問い合わせ言語はなく、書く手段もありません。",
    ),
    (
        "ask.recorded",
        "プロバイダーへの接続も、他のプロセスと同じように記録され flowlightd に帰属されます。\
         自分の通信を隠すツールに、他人の通信を見せる資格はありません。",
    ),
    (
        "ask.kind.local",
        "このマシンまたはこのネットワーク上のモデルサーバー",
    ),
    ("ask.kind.compatible", "OpenAI 互換のエンドポイント"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} は問題ありません。"),
    ("ask.safety.not_a_url", "{endpoint} は URL ではありません。"),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} は http:// でも https:// でもありません。",
    ),
    (
        "ask.safety.clear",
        "{endpoint} は、このマシンでもプライベートなネットワークでもない相手への平文の http:// です。\
         鍵と、このマシン自身の通信についての質問が、暗号化されずにネットワークを通ることになるため、\
         Flowlight はそれを送信しません。https:// を使ってください。",
    ),
    (
        "intercept.watching",
        "インターセプトは観測ではありません。Flowlight の他のすべての機能は、\
         アプリケーションが TLS ライブラリに渡すものを読むだけで、\
         ネットワークを流れるものを一切変えません。",
    ),
    (
        "intercept.agents.none",
        "エージェントが指定されていないため、何もリダイレクトされません。\
         インターセプトは、指定されたエージェントにのみ適用され、\
         このマシンの他のものには適用されません。",
    ),
    (
        "intercept.agents",
        "{agents} からの接続、およびそれらが起動したものからの接続は、このマシン上のプロキシに\
         リダイレクトされます。プロキシは TLS を終端し、外側へ自分の接続を張ります。",
    ),
    (
        "intercept.authority",
        "そのプロキシは、このマシン上で作られた認証局が署名した証明書を提示します。\
         それを信頼しないものは接続を拒否します。ピン留めされた証明書とは、まさにそう振る舞うものです。",
    ),
    (
        "intercept.passthrough",
        "モックが書かれていないホストは終端されずにそのまま通されるため、\
         証明書は理由のある場所にしか提示されません。",
    ),
    (
        "intercept.never",
        "他に何が指定されていても、次のホストは決して終端されません: {hosts}。",
    ),
    (
        "intercept.off",
        "無効にすると、リダイレクトは直ちに止まります。認証局の削除は別の手順です。\
         信頼することと信頼を取り消すことは、どちらも意図して行うべきことだからです。",
    ),
    (
        "owners.what",
        "Flowlight は、このマシンが接続したアドレスを誰が運用しているかを問い合わせます。",
    ),
    (
        "owners.question",
        "問い合わせは、Team Cymru の公開経路情報に対する DNS の照会で、{resolver} に送られます。\
         これはこのマシン自身のリゾルバー、設定されていなければ公開リゾルバーです。",
    ),
    (
        "owners.sent",
        "送信されるのはアドレスだけです。どのプロセスが到達したか、いつ、何回、\
         その他 Flowlight が知っていることは送信されません。",
    ),
    (
        "owners.local",
        "このマシンやこのネットワーク上のアドレスについては、決して問い合わせません。\
         答えはすでに分かっており、その問い合わせはあなたのネットワークについての質問になってしまいます。",
    ),
    (
        "owners.rate",
        "1 分あたり最大 4 件、通信量の多い順に、同じアドレスは二度と問い合わせません。",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask は無効です。Linux 版 Flowlight にはモデルがないため、設定が必要です。このマシン上のサーバーなら `flowlightd model --kind local --model <name>`、あるいはプロバイダーと鍵を設定してください。",
    ),
    (
        "ask.why.no_endpoint",
        "エンドポイントが設定されていないため、問い合わせる相手がありません。",
    ),
    (
        "ask.why.no_model",
        "モデル名が設定されていません。どのプロバイダーにも使用するモデルを伝える必要があり、推測してよい既定値はありません。",
    ),
    (
        "ask.why.no_key",
        "{kind} には鍵が必要ですが、保存されていません。",
    ),
    ("ask.why.unconfigured", "Ask は設定されていません。"),
    (
        "intercept.why.off",
        "インターセプトは無効です。何も終端されず、Flowlight の証明書がどこにも提示されません。",
    ),
    (
        "intercept.why.no_agents",
        "インターセプトは有効ですが、エージェントが指定されていないため何もリダイレクトされません。範囲は指定によって決まります: `flowlightd intercept --agent claude`。",
    ),
    ("owners.resolver.public", "公開リゾルバー"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "ペイロードはまったく読み取りません。接続の帰属づけは続けます。",
    ),
    (
        "budget.session.expired",
        "ペイロードの取得期間が終了し、何も読み取っていません。再開するには期間を更新してください。",
    ),
    (
        "budget.session.remaining",
        "ペイロードはあと{remaining}読み取られます。",
    ),
    (
        "budget.session.unlimited",
        "ペイロードはセッションの上限なしで読み取られています。これは要求された設定であり、既定ではありません。",
    ),
    (
        "budget.daily.none",
        "1 つのプロセスが 1 日に寄与できる量の上限はありません。",
    ),
    (
        "budget.daily",
        "1 日に {size} を超えると、そのプロセスのペイロード取得は翌日まで止まります。",
    ),
    (
        "budget.paths.full",
        "リクエストのパスは、含まれていた資格情報を取り除いたうえで、そのまま保持されます。",
    ),
    (
        "budget.paths.host",
        "保持されるのはリクエストのホストだけで、要求されたパスは保持されません。",
    ),
    (
        "budget.paths.none",
        "パスもクエリ文字列も保持しません。ホストは保持します。ホストがなければ何もまとめられないからです。",
    ),
    (
        "budget.retention",
        "個々のリクエストは{detail}、日次の要約は{summary}保持されます。",
    ),
    ("time.seconds.one", "{count}秒"),
    ("time.seconds.many", "{count}秒"),
    ("time.minutes.one", "{count}分"),
    ("time.minutes.many", "{count}分"),
    ("time.hours.one", "{count}時間"),
    ("time.hours.many", "{count}時間"),
    ("time.joined", "{hours}{minutes}"),
    ("size.bytes", "{count} バイト"),
    // The channels that are not the network.
    (
        "devices.channels",
        "これはネットワークではない経路です。USB で接続されているもの、Bluetooth でペアリングされているもの、そしてマウントされているリムーバブルボリュームです。",
    ),
    (
        "devices.no_bytes",
        "報告するのは、何が接続されているか、そしてそれがいつ変わったかです。どれだけの量が通ったかは決して報告しません。Linux はプロセスに帰属できる形でデバイスごとのバイト数を集計しておらず、誰も責任を持てない数値は数値がないよりも悪いからです。",
    ),
    (
        "devices.sources",
        "すべては、カーネルが /sys と /proc にすでに公開しているファイルから読み取ります。システムサービスには何も問い合わせず、このマシンから何も出ていきません。",
    ),
    (
        "devices.off",
        "求められるまで無効です。権限が足りないからではなく、監視の範囲を広げることになるからです。",
    ),
];
