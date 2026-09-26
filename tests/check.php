<?php
// Offline test (bez sítě): php tests/check.php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use Eet2\{Client, EetException};

// 1) Kanonizace sedí s oficiálním vzorem finanční správy
$d = new DOMDocument();
$d->load(CACHE . '/CZ683555118.eet.v4.req.xml');
$x = new DOMXPath($d);
$x->registerNamespace('s', 'http://schemas.xmlsoap.org/soap/envelope/');
$x->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$digest = base64_encode(hash('sha256', $x->query('//s:Body')->item(0)->C14N(true, false, null, ['v4']), true));
assert($digest === $x->query('//ds:DigestValue')->item(0)->textContent, 'digest vzoru nesedí');

// 2) Naše zpráva: validní podle XSD a podpis ověřitelný certifikátem
$c = Client::fromP12(P12, P12_PASS);
$xml = $c->buildSignedMessage(['eic_popl' => 'CZ683555118', 'id_jednotky' => 101, 'id_pokl' => 'P1', 'porad_cis' => 'R/1',
    'dat_trzby' => new DateTimeImmutable('2027-01-09 04:25:28', new DateTimeZone('Europe/Prague')), 'celk_trzba' => '3264.5'],
    'b3a09b52-7c87-4014-a496-4c7a53cf9125');
$m = new DOMDocument();
$m->loadXML($xml);
$mx = new DOMXPath($m);
$mx->registerNamespace('s', 'http://schemas.xmlsoap.org/soap/envelope/');
$mx->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
$mx->registerNamespace('v4', 'http://fs.gov.cz/eet/schema/v4');
$t = new DOMDocument();
$t->appendChild($t->importNode($mx->query('//v4:Trzba')->item(0), true));
assert($t->schemaValidate(CACHE . '/EETXMLSchema.xsd'), 'zpráva neodpovídá XSD');
assert(strlen($xml) < 12 * 1024, 'zpráva přesahuje 12 kB');
assert($mx->query('//v4:Data/@dat_trzby')->item(0)->value === '2027-01-09T04:25:28+01:00');
$cert = "-----BEGIN CERTIFICATE-----\n" . chunk_split($mx->query('//*[local-name()="BinarySecurityToken"]')->item(0)->textContent, 64) . "-----END CERTIFICATE-----\n";
$si = $mx->query('//ds:SignedInfo')->item(0)->C14N(true, false, null, ['soapenv', 'v4']);
assert(openssl_verify($si, base64_decode($mx->query('//ds:SignatureValue')->item(0)->textContent), $cert, OPENSSL_ALGO_SHA256) === 1, 'podpis neplatí');

// 3) Formát částek dle specifikace
foreach (['20.45' => '20.45', '0' => '0.00', '-0.001' => '0.00', '0.2' => '0.20', '-100' => '-100.00', '99999999.99' => '99999999.99'] as $in => $out) {
    assert(Client::formatAmount($in) === $out, "formatAmount($in)");
}
try { Client::formatAmount('100000000'); assert(false); } catch (EetException) {}

// 4) Parsování odpovědí (vzory ze specifikace)
$ns = 'xmlns:tns="http://fs.gov.cz/eet/schema/v4"';
$r = Client::parseResponse("<tns:Odpoved $ns><tns:Hlavicka/><tns:Potvrzeni pok=\"987a6be5-6af5-44f3-b4fc-987654321000-ff\" test=\"true\"/><tns:Varovani kod_varov=\"1\">EIC nesedi</tns:Varovani></tns:Odpoved>", 200, 'u', null);
assert($r['pok'] === '987a6be5-6af5-44f3-b4fc-987654321000-ff' && $r['test'] && $r['warnings'] === [1 => 'EIC nesedi']);
try {
    Client::parseResponse("<tns:Odpoved $ns><tns:Hlavicka/><tns:Chyba kod=\"-1\">Docasna chyba</tns:Chyba></tns:Odpoved>", 200, 'u', null);
    assert(false);
} catch (EetException $e) { assert($e->isRetryable()); }

// 5) Podpis skutečné odpovědi Playgroundu projde, podvržený POK ne
$resp = file_get_contents(__DIR__ . '/fixtures/response-ok.xml');
Client::verifyResponseSignature($resp);
try {
    Client::verifyResponseSignature(str_replace('pok="2feb', 'pok="3feb', $resp));
    assert(false, 'podvržená odpověď prošla');
} catch (EetException $e) { assert($e->getCode() === EetException::SIGNATURE_INVALID && $e->isRetryable()); }
assert(Client::fromP12(P12, P12_PASS)->certificateExpiresAt() > new DateTimeImmutable());

echo "OK\n";
