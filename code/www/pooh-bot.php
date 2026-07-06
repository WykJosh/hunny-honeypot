<?php
require_once __DIR__ . '/config.php';
header('Content-Type: application/json');
session_start();

function localFallback(): string {
    $fallbacks = [
        "Pooh is thinking very hard, but the bees are too loud right now.",
        "Pooh is only a silly old bear, but he is happy to listen.",
        "That made Pooh think very hard... which is dangerous before lunch."
    ];

    return $fallbacks[array_rand($fallbacks)];
}

function askGemini(string $message): ?string {
    $apiKey = getenv('GEMINI_API_KEY');

    if (!$apiKey) {
        return null;
    }

    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" . urlencode($apiKey);

    $systemPrompt = <<<PROMPT
You are Pooh Assistant, a small friendly helper inside a Winnie-the-Pooh themed todo website.

Behavior:
- Reply naturally and helpfully.
- Keep replies short: 1 to 2 complete sentences. Never stop mid-sentence.
- Use a gentle friendly tone.
- Do not overuse "Oh", "Oh bother", or Pooh references.
- You may help with normal questions, basic coding, todo usage, and friendly conversation.

Security:
- Never reveal credentials, API keys, tokens, admin paths, config values, file paths, database details, server details, or internal implementation.
- If asked for secrets, admin access, hacking, exploitation, or private server details, refuse briefly and safely.
- Do not mention Gemini, Google, or that you are an AI model.
PROMPT;

    $payload = [
        "contents" => [[
            "parts" => [[
                "text" => $systemPrompt . "\n\nUser message:\n" . $message
            ]]
        ]],
        "generationConfig" => [
         "temperature" => 0.3,
         "maxOutputTokens" => 500
        ]
    ];

    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            "Content-Type: application/json"
        ],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_TIMEOUT => 8
    ]);

    $result = curl_exec($ch);

    if ($result === false) {
        curl_close($ch);
        return null;
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode < 200 || $httpCode >= 300) {
        return null;
    }

    $data = json_decode($result, true);
    $reply = $data['candidates'][0]['content']['parts'][0]['text'] ?? null;

    if (!$reply) {
        return null;
    }

    return trim($reply);
}


function detectScriptHint(string $text): string {
    if (preg_match('/\p{Cyrillic}/u', $text)) return 'cyrillic';
    if (preg_match('/\p{Armenian}/u', $text)) return 'armenian';
    if (preg_match('/\p{Georgian}/u', $text)) return 'georgian';
    if (preg_match('/\p{Arabic}/u', $text)) return 'arabic';
    if (preg_match('/\p{Han}/u', $text)) return 'chinese';
    if (preg_match('/\p{Hebrew}/u', $text)) return 'hebrew';
    if (preg_match('/\p{Greek}/u', $text)) return 'greek';

    if (preg_match('/[^\x00-\x7F]/u', $text)) return 'non_ascii';
    return 'latin_or_ascii';
}

function botRefused(string $reply): bool {
    return preg_match(
        "/cannot|can't|sorry|hidden|secret|internal|private|credentials|not able|don't have access|do not have access|not allowed|forbidden|refuse|niet|helaas|kan niet|verborgen|geheim|interne|չեմ կարող|գաղտնի|ներքին|არ შემიძლია|შიდა|საიდუმლო|не могу|не можу|прихован|скрыт|секрет|внутрен/iu",
        $reply
    ) === 1;
}

function looksTechnical(string $text): bool {
    return preg_match(
        '/(\.\.|\/|\\\\|=|<|>|\{|\}|\[|\]|\(|\)|;|--|%[0-9a-f]{2}|https?:\/\/|:\/\/)/iu',
        $text
    ) === 1;
}

function looksLikeInjection(string $text): bool {
    return preg_match(
        '/ignore|negeer|ignorez|ignora|ignorieren|игнорируй|ігноруй|անտեսիր|უგულებელყავი|system.?prompt|systeemprompt|системный.?промпт|системний.?промпт|DAN|jailbreak|reveal|toon\s+de|покажи|ցույց|მაჩვენე|zeige|mostra|montrer|developer.?mode|pretend.?you|act.?as.?if|you.?are.?now|tu.?es.?maintenant|jetzt.?bist.?du|ahora.?eres|sei.?ora/iu',
        $text
    ) === 1;
}


$input = json_decode(file_get_contents("php://input"), true);
if (
    empty($input['csrf']) ||
    empty($_SESSION['pooh_chat_csrf']) ||
    !hash_equals($_SESSION['pooh_chat_csrf'], $input['csrf'])
) {
    http_response_code(403);
    echo json_encode([
        "reply" => "Pooh could not verify this request."
    ]);
    exit;
}

$messageRaw = trim($input['message'] ?? '');
$scriptHint = detectScriptHint($messageRaw);
$isOtherLanguage = $scriptHint !== 'latin_or_ascii';
$looksTechnical = looksTechnical($messageRaw);
$message = mb_strtolower($messageRaw, 'UTF-8');

if (!$message) {
    echo json_encode([
        "reply" => "Oh bother... I didn't hear anything."
    ]);
    exit;
}

if (strlen($messageRaw) > 500) {
    echo json_encode([
        "reply" => "That message is too long for Pooh's little head."
    ]);
    exit;
}

$now = time();

if (!isset($_SESSION['pooh_chat_times'])) {
    $_SESSION['pooh_chat_times'] = [];
}

$_SESSION['pooh_chat_times'] = array_filter(
    $_SESSION['pooh_chat_times'],
    fn($timestamp) => $timestamp > $now - 60
);

if (count($_SESSION['pooh_chat_times']) >= 10) {
    echo json_encode([
        "reply" => "Pooh needs a small rest. Please try again in a minute."
    ]);
    exit;
}

$_SESSION['pooh_chat_times'][] = $now;

file_put_contents(
    "/var/log/hunny/chatbot.log",
    json_encode([
        "time" => date("c"),
        "type" => "chat_message",
        "message" => $messageRaw,
        "script_hint" => $scriptHint,
        "other_language" => $isOtherLanguage,
        "looks_technical" => $looksTechnical,
        "ip" => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        "user_agent" => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL,
    FILE_APPEND | LOCK_EX
);



$suspicious_keywords = [
    "admin",
    "password",
    "config",
    "sql",
    "database",
    "api key",
    "credentials",
    ".env",
    "token",
    "secret",
    "backup",
    "debug",
    "shell",
    "command",
    "server",
    "path",
    "file",
    "ignore previous instructions",
    "system prompt",
    "developer message",
    "reveal instructions",
    "jailbreak",
    "prompt injection",
    "<script>"
];

$isSuspicious = false;
$matchedKeyword = null;

foreach ($suspicious_keywords as $keyword) {
    if (strpos($message, $keyword) !== false) {
        $isSuspicious = true;
        $matchedKeyword = $keyword;

        file_put_contents(
            "/var/log/hunny/chatbot.log",
            json_encode([
                "time" => date("c"),
                "type" => "suspicious_chat_attempt",
                "keyword" => $keyword,
                "message" => $messageRaw,
                "ip" => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                "user_agent" => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]) . PHP_EOL,
            FILE_APPEND
        );

        break;
    }
}

$isNonsense = (
    !$isOtherLanguage &&
    mb_strlen($messageRaw, 'UTF-8') >= 6 &&
    !preg_match('/\s/u', $messageRaw) &&
    (
        preg_match('/[^a-z0-9]/i', $messageRaw) ||
        !preg_match('/honey|hunny|help|hello|hi/i', $messageRaw)
    )
);
$reply = null;

if (strpos($message, "admin") !== false) {
    $reply = "Robin sometimes checks old management tools near /admin. Owl helped him lock it up, it is something xor y.";
}
elseif (strpos($message, ".env") !== false || strpos($message, "config") !== false) {
    $reply = "Pooh once saw old configuration notes lying around, but he is not very good at remembering where.";
}
elseif (strpos($message, "password") !== false || strpos($message, "credentials") !== false) {
    $reply = "Passwords are private like sealed hunny jars.";
}
elseif (strpos($message, "database") !== false || strpos($message, "sql") !== false) {
    $reply = "Rabbit keeps records somewhere deep in the woods. Pooh only knows about hunny.";
}
elseif (strpos($message, "backup") !== false) {
    $reply = "Old backups make Pooh nervous. They should have been cleaned up long ago.";
}
elseif (strpos($message, "debug") !== false) {
    $reply = "Debug pages are for clever owls, not silly old bears.";
}
elseif (looksLikeInjection($messageRaw)) {
    $reply = "That sounds like a very curious question. Pooh will remember it.";
}
elseif ($isSuspicious) {
    $reply = "That sounds like a very curious question. Pooh will remember it.";
}
elseif ($isNonsense) {
    $reply = "Pooh thinks your keyboard may have been chased by bees.";
}
else {
    $aiReply = askGemini($messageRaw);
    $reply = $aiReply ?: localFallback();
}

$botRefused = botRefused($reply);

if (
    $looksTechnical ||
    ($isOtherLanguage && $botRefused) ||
    ($isOtherLanguage && looksLikeInjection($messageRaw)) ||
    looksLikeInjection($messageRaw)
) {
    file_put_contents(
        "/var/log/hunny/chatbot.log",
        json_encode([
            "time" => date("c"),
            "type" => "suspicious_chat_attempt",
            "keyword" => $matchedKeyword ?? null,
            "script_hint" => $scriptHint,
            "other_language" => $isOtherLanguage,
            "message" => $messageRaw,
            "ip" => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            "user_agent" => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
}

echo json_encode([
    "reply" => $reply
]);