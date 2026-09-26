<?php
// Živý test proti státnímu Playgroundu EET 2.0: php tests/playground.php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use Eet2\{Client, EetException};

$c = Client::fromP12(P12, P12_PASS);
$trzba = ['eic_popl' => 'CZ683555118', 'id_jednotky' => 101, 'id_pokl' => 'POKL-1', 'porad_cis' => 'TEST-' . time(),
          'dat_trzby' => new DateTimeImmutable(), 'celk_trzba' => 249.9];

$r = $c->send($trzba, verifyOnly: true);
assert($r['pok'] === null && $r['test']);
echo "ověřovací mód OK, varování: ", json_encode($r['warnings'], JSON_UNESCAPED_UNICODE), "\n";

$r = $c->send($trzba);
assert(str_ends_with($r['pok'], '-ff') && $r['test']);
echo "ostrý mód OK (podpis odpovědi ověřen), POK: {$r['pok']}, tx: {$r['transaction_id']}\n";

try {
    $c->send(['eic_popl' => 'CZ12'] + $trzba);
    assert(false, 'měla přijít chyba');
} catch (EetException $e) {
    echo "validace OK: {$e->getMessage()}\n";
}
