<?php
// Stáhne veřejné testovací soubory finanční správy (certifikáty, XSD, vzor) do tests/.cache - v repu je nešíříme.
declare(strict_types=1);
error_reporting(E_ALL);
require __DIR__ . '/../src/EetException.php';
require __DIR__ . '/../src/Client.php';

const CACHE = __DIR__ . '/.cache';
const P12 = CACHE . '/CA_EET-Playground-CZ683555118.p12';
const P12_PASS = 'aaaa1111';

if (!is_file(P12)) {
    @mkdir(CACHE);
    $base = 'https://eet.gov.cz/assets/cs/cmsmedia/pro-vyvojare/';
    foreach (['CAEET_Playground_2026_v1.zip', 'EETXMLSchema.xsd', 'CZ683555118.eet.v4.req.xml'] as $f) {
        $data = file_get_contents($base . $f) ?: throw new RuntimeException("Stažení $f selhalo");
        file_put_contents(CACHE . "/$f", $data);
    }
    $zip = new ZipArchive();
    $zip->open(CACHE . '/CAEET_Playground_2026_v1.zip') === true || throw new RuntimeException('Nelze otevřít ZIP');
    $zip->extractTo(CACHE);
    $zip->close();
}
