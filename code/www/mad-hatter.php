<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/layout.php';


$fake_db_rows = [
    ['id' => 1,  'username' => 'admin',   'email' => 'admin@honeypot.local',         'is_admin' => 1, 'created_at' => '2026-04-01 00:00:01', 'password_hash' => '$2y$12$Kx8QwZvLmNpRtYuOiAsDfGhJkLzXcVbNmQwErTyUiOpAsdfGhjkl'],
    ['id' => 2,  'username' => 'pooh',    'email' => 'pooh@hundredacre.local',        'is_admin' => 0, 'created_at' => '2026-04-13 09:22:14', 'password_hash' => '$2y$12$Ax9BcDeFgHiJkLmNoPqRsT1uVwXyZaBcDeFgHiJkLmNoPqRsTuVw'],
    ['id' => 4,  'username' => 'tigger',  'email' => 'tigger@hundredacre.local',      'is_admin' => 0, 'created_at' => '2026-04-20 11:45:33', 'password_hash' => '$2y$12$Bz8CdEfGhIjKlMnOpQrStU2vWxYzAbCdEfGhIjKlMnOpQrStUvWx'],
    ['id' => 6,  'username' => 'rabbit',  'email' => 'rabbit@hundredacre.local',      'is_admin' => 0, 'created_at' => '2026-04-22 14:08:52', 'password_hash' => '$2y$12$Cy7DeEfGhIjKlMnOpQrSt3UvWxYzAbCdEfGhIjKlMnOpQrStUvWx'],
    ['id' => 7,  'username' => 'a587dfv78', 'email' => 'a587dfv78@hundredacre.local', 'is_admin' => 0, 'created_at' => '2026-05-01 10:00:00', 'password_hash' => '$2y$12$ExampleHashStringForUserA587dfv78'],
    ['id' => 8,  'username' => 'k92xmpl34', 'email' => 'k92xmpl34@hundredacre.local', 'is_admin' => 0, 'created_at' => '2026-05-01 10:05:00', 'password_hash' => '$2y$12$ExampleHashStringForUserK92xmpl34'],
];

const SQLI_FAKE_FIELDS  = ['b1', 'b7'];
const SQLI_TIGGER_FIELD = 'b15';


function detect_attack_type(string $val): string
{
    if (preg_match('/<script|onerror\s*=|onload\s*=|javascript:|<img|<svg|alert\s*\(|document\.|window\./i', $val))
        return 'XSS_ATTEMPT';
    if (preg_match('/\'\s*(or|and)\s*[\'\\d]|union\s+select|--\s*$|;\s*drop|;\s*select|1\s*=\s*1/i', $val))
        return 'SQLI_ATTEMPT';
    if (preg_match('/\.\.[\\/\\\\]|\/etc\/|\/proc\/|\/var\/www/i', $val))
        return 'PATH_TRAVERSAL';
    if (preg_match('/;\s*(ls|cat|whoami|id|pwd|wget|curl)|[`|]\s*(ls|cat|id)/i', $val))
        return 'CMD_INJECTION';
    return 'INPUT_PROBE';
}

$field_responses = [];
$submitted       = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;

    // Honeytoken
    if (!empty($_POST['hp_check'])) {
        log_honeypot('mad_hatter_bot', 'mad_hatter', ['field_value' => $_POST['hp_check']]);
    }

    foreach ($_POST as $field => $val) {
        if ($field === 'hp_check' || $field === 'csrf_token') continue;
        $val = (string)$val;
        if (trim($val) === '') continue;

        $type = detect_attack_type($val);

        // /var/log/hunny/honeypot.log 
        log_honeypot('mad_hatter_' . strtolower($type), 'mad_hatter', [
            'field'    => $field,
            'payload'  => $val,
        ]);

        if ($type === 'SQLI_ATTEMPT') {
            if (in_array($field, SQLI_FAKE_FIELDS, true)) {
                $field_responses[$field] = ['type' => 'sqli_fake',   'raw' => $val];
            } else {
                $field_responses[$field] = ['type' => 'sqli_tigger', 'raw' => $val];
            }
        } elseif ($type === 'XSS_ATTEMPT') {
            //the attack is logged but will NOT execute.
            $field_responses[$field] = ['type' => 'xss_blocked', 'raw' => $val, 'safe' => h($val)];
        } elseif ($type === 'CMD_INJECTION' || $type === 'PATH_TRAVERSAL') {
            $field_responses[$field] = ['type' => 'rce_blocked', 'raw' => $val];
        } else {
            $field_responses[$field] = ['type' => 'echo', 'raw' => $val, 'safe' => h($val)];
        }
    }
}

$bubbles = [
    ['label' => 'Am I SQL infected? 🤒',                               'name' => 'b1',  'type' => 'text',     'size' => 'med'],
    ['label' => "Can u speak snake? Cuz u seem like u could XSS̶S̶S̶S̶ 🐍", 'name' => 'b2',  'type' => 'text',     'size' => 'wide'],
    ['label' => 'Am I just a comment to you? --',                      'name' => 'b3',  'type' => 'text',     'size' => 'small'],
    ['label' => 'Database query console (totally real)',                'name' => 'b7',  'type' => 'text',     'size' => 'wide'],
    ['label' => 'Your totally normal username',                         'name' => 'b8',  'type' => 'text',     'size' => 'small'],
    ['label' => "DROP TABLE feelings; -- 💔",                           'name' => 'b9',  'type' => 'text',     'size' => 'med'],
    ['label' => 'File path (nothing to see here)',                   'name' => 'b10', 'type' => 'text',     'size' => 'small'],
    ['label' => 'Execute a spell',                                     'name' => 'b11', 'type' => 'text',     'size' => 'med'],
    ['label' => "What's the password? (it's definitely not password)",  'name' => 'b12', 'type' => 'password', 'size' => 'wide'],
    ['label' => 'Enter your XSS-tra special code :P',                  'name' => 'b13', 'type' => 'text',     'size' => 'small'],
    ['label' => 'Totally secure input field',               'name' => 'b14', 'type' => 'text',     'size' => 'med'],
    ['label' => "Union? Select? I barely know her",                    'name' => 'b15', 'type' => 'text',     'size' => 'small'],
    ['label' => 'Shell command (absolutely not dangerous)',             'name' => 'b16', 'type' => 'text',     'size' => 'med'],
    ['label' => "I'm not a trap. Promise.",                          'name' => 'b17', 'type' => 'text',     'size' => 'small'],
    ['label' => 'Admin backdoor (shhh)',                             'name' => 'b18', 'type' => 'text',     'size' => 'wide'],
    ['label' => "SELECT * FROM my_heart WHERE broken = 1",             'name' => 'b19', 'type' => 'text',     'size' => 'small'],
    ['label' => "Oh you're a hacker? Name every injection 🙄",         'name' => 'b21', 'type' => 'text',     'size' => 'wide'],
    ['label' => 'API key (I lost mine, maybe yours works)',            'name' => 'b22', 'type' => 'text',     'size' => 'med'],
    ['label' => "1' OR '1'='1",                                        'name' => 'b23', 'type' => 'text',     'size' => 'small'],
    ['label' => 'Root password to the universe',                       'name' => 'b24', 'type' => 'password', 'size' => 'small'],
    ['label' => 'Definitely not logging this',                      'name' => 'b25', 'type' => 'text',     'size' => 'med'],
    ['label' => 'Tag yourself (html tags welcome)',                    'name' => 'b26', 'type' => 'text',     'size' => 'wide'],
];

$user = start_page('Winnie pooh\'s Riddle Emporium');
?>




<div class="mh-hero">
    <h1 class="mh-hero-title">Winnie pooh's<br>Riddle Emporium</h1>
</div>

<?php if ($submitted && !empty($field_responses)): ?>
    <!-- response cards -->
    <div class="mh-responses">
        <div class="mh-response-card" style="border-left-color:var(--honey-dark)">
            <strong>we have received your messages, thanks.</strong>
            <span style="color:var(--bark-light);font-size:0.82rem;margin-left:0.5rem">

            </span>
        </div>

        <?php foreach ($field_responses as $field => $resp): ?>

            <div class="mh-response-wrap">
                <img class="mh-tigger-top" src="/images/tigger.gif" alt="Tigger bouncing" />

                <?php if ($resp['type'] === 'sqli_fake'): ?>
                    <!--  SQL injection - fake DB dump  -->
                    <div class="mh-response-card sqli-fake">
                        <div class="sqli-query-echo">
                            mysql&gt; <?= h($resp['raw']) ?><span style="animation:blink 1s step-end infinite">█</span>
                        </div>
                        <table>
                            <thead>
                                <tr>
                                    <th>id</th>
                                    <th>username</th>
                                    <th>email</th>
                                    <th>is_admin</th>
                                    <th>created_at</th>
                                    <th>password_hash</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($fake_db_rows as $row): ?>
                                    <tr>
                                        <td><?= $row['id'] ?></td>
                                        <td><?= h($row['username']) ?></td>
                                        <td><?= h($row['email']) ?></td>
                                        <td><?= $row['is_admin'] ?></td>
                                        <td><?= h($row['created_at']) ?></td>
                                        <td class="hash"><?= h($row['password_hash']) ?>...</td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        <div class="sqli-footer">
                            <?= count($fake_db_rows) ?> rows in set (0.00 sec) &nbsp;|&nbsp;
                            Query OK &nbsp;|&nbsp; Rows matched: <?= count($fake_db_rows) ?>
                        </div>
                    </div>

                <?php elseif ($resp['type'] === 'sqli_tigger'): ?>
                    <!--  SQL injection - Tigger oops  -->
                    <div class="mh-response-card sqli-tigger">
                        <div class="tigger-msg">shaaame :P</div>
                        <a href="https://www.youtube.com/shorts/yNUoyU4_gAo">check 1.1</a>
                    </div>

                <?php elseif ($resp['type'] === 'xss_blocked'): ?>
                    <!-- xss -->
                    <div class="mh-response-card xss-blocked">
                        <div class="xss-status">Rendered safely!</div>
                        <div class="xss-payload"><?= $resp['safe'] ?></div>
                        <div style="margin-top:0.4rem;font-size:0.78rem;color:var(--bark-light)">
                            Looks like something went a bit salty there.
                            Pooh doesn't like salty, he likes sweet
                        </div>
                        <a href="https://www.youtube.com/watch?v=Pm1qzfbRAPw"></a>
                    </div>

                <?php elseif ($resp['type'] === 'rce_blocked'): ?>
                    <!--  cmd + path traversal  -->
                    <div class="mh-response-card rce-blocked">
                        <div class="rce-msg">
                            $ <span style="color:#8e44ad"><?= h(substr($resp['raw'], 0, 60)) ?></span><br>
                            <span style="color:#27ae60">bash: permission denied — this is the Hundred Acre Wood, not a terminal </span>
                        </div>
                    </div>

                <?php else: ?>
                    <!--  Normal input echo  -->
                    <div class="mh-response-card echo-card">
                        <div class="echo-val"><?= $resp['safe'] ?>
                        </div>
                        <a href="https://www.youtube.com/watch?v=5R8XHrfJkeg">check 1.3</a>


                    </div>

                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<!--  Bubble form -->
<form method="POST" action="/mad-hatter.php">
    <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>" />

    <!-- for bots -->
    <div class="mh-hp-trap" aria-hidden="true">
        <input type="text" name="hp_check" tabindex="-1" autocomplete="off" />
    </div>

    <div class="mh-bubble-canvas" id="bubbleCanvas">

        <?php
        $positions = [
            // Row 0 
            [5,   50, 'med',   ''],
            [34,   22, 'wide',  ''],
            [58,   68, 'small', 'drip'],
            [76,   40, 'med',   ''],
            // Row 1
            [8,  200, 'small', ''],
            [30,  210, 'med',   'drip'],
            [55,  195, 'wide',  ''],
            [78,  215, 'small', ''],
            // Row 2 
            [12,  400, 'wide',  ''],
            [38,  385, 'small', 'drip'],
            [60,  410, 'med',   ''],
            [80,  390, 'med',   ''],
            // Row 3  
            [5,  600, 'small', ''],
            [25,  580, 'med',   ''],
            [50,  595, 'wide',  'drip'],
            [76,  615, 'small', ''],
            // Row 4 
            [10,  790, 'med',   'drip'],
            [33,  775, 'wide',  ''],
            [60,  800, 'small', ''],
            [78,  780, 'med',   ''],
            // Row 5  
            [22,  980, 'wide',  ''],
            [58,  960, 'med',   'drip'],
        ];

        foreach ($bubbles as $i => $b):
            $pos   = $positions[$i] ?? [rand(5, 80), 200 + $i * 120, 'med', ''];
            $left  = $pos[0];
            $top   = $pos[1];
            $size  = $pos[2];
            $extra = $pos[3];
            $uid   = 'input_' . $b['name'];
        ?>
            <div class="mh-bubble <?= $size ?> <?= $extra ?>"
                style="left:<?= $left ?>%; top:<?= $top ?>px;">
                <label for="<?= $uid ?>"><?= $b['label'] ?></label>
                <input type="<?= $b['type'] ?>"
                    id="<?= $uid ?>"
                    name="<?= $b['name'] ?>"
                    autocomplete="off"
                    placeholder="..." />
            </div>
        <?php endforeach; ?>

        <div class="mh-submit-zone">
            <button type="submit" class="mh-submit-blob">
                Send to<br> pooh
            </button>
        </div>

    </div>
</form>


<?php end_page(); ?>

<script>
    // Tiny wobble on click
    document.querySelectorAll('.mh-bubble').forEach(b => {
        b.addEventListener('click', function() {
            this.style.transition = 'transform 0.1s';
            this.style.transform = 'scale(0.96) rotate(2deg)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    });
</script>

<?php

?>