<?php

declare(strict_types=1);

namespace Eet2;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use DOMDocument;
use DOMXPath;

/**
 * Klient pro EET 2.0 (rozhraní v4, SOAP + WS-Security).
 * Bez závislostí: jen ext-dom, ext-openssl, ext-curl.
 */
final class Client
{
    public const PRODUCTION = 'https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4';
    public const PLAYGROUND = 'https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4';

    private const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const NS_EET = 'http://fs.gov.cz/eet/schema/v4';
    private const NS_WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const NS_WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_EC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var \OpenSSLAsymmetricKey */
    private $key;
    private string $certBase64;

    /** organizationIdentifier Generálního finančního ředitelství v certifikátu, kterým EET podepisuje potvrzení */
    private const GFR_ID = 'NTRCZ-72080043';

    /**
     * @param bool $verifyResponses ověřit podpis potvrzení (certifikát GFŘ vydaný I.CA) - vypínat jen pro ladění
     */
    public function __construct(
        string $privateKeyPem,
        string $certPem,
        private string $url = self::PLAYGROUND,
        private int $timeout = 5,
        private bool $verifyResponses = true,
    ) {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new EetException('Nelze načíst privátní klíč: ' . openssl_error_string());
        }
        $this->key = $key;
        if (!openssl_x509_export($certPem, $out)) {
            throw new EetException('Nelze načíst certifikát: ' . openssl_error_string());
        }
        $this->certBase64 = preg_replace('/-----[^-]+-----|\s/', '', $out);
    }

    /**
     * Načte pokladní certifikát (.p12) z DIS+. Certifikáty CA EET jsou šifrované RC2-40,
     * které OpenSSL 3 bez "legacy" provideru nenačte - v tom případě se použije CLI `openssl -legacy`.
     */
    public static function fromP12(string $path, string $password, string $url = self::PLAYGROUND, int $timeout = 5, bool $verifyResponses = true): self
    {
        ['key' => $key, 'cert' => $cert] = self::readP12($path, $password);
        return new self($key, $cert, $url, $timeout, $verifyResponses);
    }

    /**
     * Přečte .p12 z DIS+ na PEM klíč a certifikát. Certifikáty CA EET jsou šifrované RC2-40,
     * které OpenSSL 3 bez "legacy" provideru nenačte - v tom případě se použije CLI `openssl -legacy`.
     *
     * @return array{key: string, cert: string}
     */
    public static function readP12(string $path, string $password): array
    {
        $p12 = @file_get_contents($path);
        if ($p12 === false) {
            throw new EetException("Soubor $path nelze přečíst");
        }
        if (openssl_pkcs12_read($p12, $certs, $password)) {
            openssl_pkey_export($certs['pkey'], $key);
            return ['key' => $key, 'cert' => $certs['cert']];
        }
        $proc = proc_open(
            ['openssl', 'pkcs12', '-legacy', '-in', $path, '-nodes', '-passin', 'env:EET_P12_PASS'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            ['EET_P12_PASS' => $password, 'PATH' => getenv('PATH') ?: '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin'],
        );
        $pem = $proc ? stream_get_contents($pipes[1]) : '';
        $err = $proc ? stream_get_contents($pipes[2]) : 'proc_open selhal';
        if (!$proc || proc_close($proc) !== 0) {
            throw new EetException('Certifikát nelze načíst (špatné heslo nebo chybí openssl CLI): ' . trim($err));
        }
        preg_match('/-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----/s', $pem, $k);
        // první certifikát v souboru je certifikát poplatníka, další jsou CA
        preg_match('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $c);
        if (!$k || !$c) {
            throw new EetException('V .p12 chybí klíč nebo certifikát');
        }
        return ['key' => $k[0], 'cert' => $c[0]];
    }

    /** Konec platnosti pokladního certifikátu (certifikáty CA EET platí 366 dní). */
    public function certificateExpiresAt(): DateTimeImmutable
    {
        $info = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . chunk_split($this->certBase64, 64) . "-----END CERTIFICATE-----\n");
        return (new DateTimeImmutable())->setTimestamp($info['validTo_time_t']);
    }

    /**
     * Odešle tržbu. Povinné klíče: eic_popl, id_jednotky, id_pokl, porad_cis, dat_trzby, celk_trzba.
     * Nepovinné: eic_poverujiciho, povereni_vice_popl, urceno_cerp_zuct, cerp_zuct.
     * Částky jako float/int/string v Kč, dat_trzby jako DateTimeInterface.
     *
     * @param array<string, mixed> $trzba
     * @return array{pok: ?string, test: bool, uuid: string, warnings: array<int, string>, transaction_id: ?string}
     * @throws EetException kód chyby EET; isRetryable() = odeslat znovu s prvni_zaslani=false
     */
    public function send(array $trzba, bool $firstAttempt = true, bool $verifyOnly = false): array
    {
        $uuid = self::uuid4();
        $xml = $this->buildSignedMessage($trzba, $uuid, $firstAttempt, $verifyOnly);
        [$status, $body, $txId] = $this->post($xml);
        $result = self::parseResponse($body, $status, $uuid, $txId, $verifyOnly);
        if ($result['pok'] !== null && $this->verifyResponses) {
            self::verifyResponseSignature($body);
        }
        return $result;
    }

    /**
     * Ověří podpis potvrzovací zprávy: otisk těla, podpis, a že certifikát patří GFŘ a je vydán I.CA.
     * @throws EetException s kódem EetException::SIGNATURE_INVALID
     */
    public static function verifyResponseSignature(string $body): void
    {
        $fail = static fn (string $why) => new EetException("Neplatný podpis odpovědi EET: $why", EetException::SIGNATURE_INVALID);
        $doc = new DOMDocument();
        if (!@$doc->loadXML($body)) {
            throw $fail('nečitelné XML');
        }
        $x = new DOMXPath($doc);
        $x->registerNamespace('s', self::NS_SOAP);
        $x->registerNamespace('ds', self::NS_DS);
        $x->registerNamespace('wsse', self::NS_WSSE);
        $bodyEl = $x->query('/s:Envelope/s:Body')->item(0);
        $ref = $x->query('//ds:SignedInfo/ds:Reference')->item(0);
        $token = $x->query('//wsse:BinarySecurityToken')->item(0);
        $sigValue = $x->query('//ds:SignatureValue')->item(0);
        if (!$bodyEl || !$ref || !$token || !$sigValue) {
            throw $fail('chybí podpis');
        }
        // podepsaný musí být právě element Body této zprávy
        if ($ref->getAttribute('URI') !== '#' . $bodyEl->getAttributeNS(self::NS_WSU, 'Id')) {
            throw $fail('podpis neodkazuje na tělo zprávy');
        }
        $digest = base64_encode(hash('sha256', $bodyEl->C14N(true, false), true));
        if (!hash_equals($digest, trim($x->query('ds:DigestValue', $ref)->item(0)?->textContent ?? ''))) {
            throw $fail('otisk těla nesedí');
        }
        $cert = "-----BEGIN CERTIFICATE-----\n" . chunk_split(preg_replace('/\s/', '', $token->textContent), 64) . "-----END CERTIFICATE-----\n";
        $info = openssl_x509_parse($cert);
        if (!$info || ($info['subject']['organizationIdentifier'] ?? '') !== self::GFR_ID) {
            throw $fail('certifikát nepatří GFŘ');
        }
        if (openssl_x509_checkpurpose($cert, X509_PURPOSE_ANY, [dirname(__DIR__) . '/res/ica-chain.pem']) !== true) {
            throw $fail('certifikát není vydán I.CA nebo vypršel');
        }
        $signedInfo = $x->query('//ds:SignedInfo')->item(0)->C14N(true, false);
        if (openssl_verify($signedInfo, base64_decode($sigValue->textContent), $cert, OPENSSL_ALGO_SHA256) !== 1) {
            throw $fail('podpis nesedí');
        }
    }

    /** @param array<string, mixed> $trzba */
    public function buildSignedMessage(array $trzba, string $uuid, bool $firstAttempt = true, bool $verifyOnly = false): string
    {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $env = $doc->createElementNS(self::NS_SOAP, 'soapenv:Envelope');
        $env->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:v4', self::NS_EET);
        $doc->appendChild($env);
        $header = $env->appendChild($doc->createElementNS(self::NS_SOAP, 'soapenv:Header'));
        $body = $env->appendChild($doc->createElementNS(self::NS_SOAP, 'soapenv:Body'));
        $body->setAttributeNS(self::NS_WSU, 'wsu:Id', 'Body');

        $t = $body->appendChild($doc->createElementNS(self::NS_EET, 'v4:Trzba'));
        $h = $t->appendChild($doc->createElementNS(self::NS_EET, 'v4:Hlavicka'));
        $h->setAttribute('uuid_zpravy', $uuid);
        $h->setAttribute('dat_odesl', self::formatDate(new DateTimeImmutable()));
        $h->setAttribute('prvni_zaslani', $firstAttempt ? 'true' : 'false');
        if ($verifyOnly) {
            $h->setAttribute('overeni', 'true');
        }
        $d = $t->appendChild($doc->createElementNS(self::NS_EET, 'v4:Data'));
        foreach (self::normalize($trzba) as $name => $value) {
            $d->setAttribute($name, $value);
        }

        $sec = $header->appendChild($doc->createElementNS(self::NS_WSSE, 'wsse:Security'));
        $bst = $sec->appendChild($doc->createElementNS(self::NS_WSSE, 'wsse:BinarySecurityToken', $this->certBase64));
        $bst->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
        $bst->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $bst->setAttributeNS(self::NS_WSU, 'wsu:Id', 'X509');

        $sig = $sec->appendChild($doc->createElementNS(self::NS_DS, 'ds:Signature'));
        $si = $sig->appendChild($doc->createElementNS(self::NS_DS, 'ds:SignedInfo'));
        $cm = $si->appendChild($doc->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod'));
        $cm->setAttribute('Algorithm', self::NS_EC);
        $cm->appendChild($doc->createElementNS(self::NS_EC, 'ec:InclusiveNamespaces'))->setAttribute('PrefixList', 'soapenv v4');
        $si->appendChild($doc->createElementNS(self::NS_DS, 'ds:SignatureMethod'))
            ->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        $ref = $si->appendChild($doc->createElementNS(self::NS_DS, 'ds:Reference'));
        $ref->setAttribute('URI', '#Body');
        $tr = $ref->appendChild($doc->createElementNS(self::NS_DS, 'ds:Transforms'))
            ->appendChild($doc->createElementNS(self::NS_DS, 'ds:Transform'));
        $tr->setAttribute('Algorithm', self::NS_EC);
        $tr->appendChild($doc->createElementNS(self::NS_EC, 'ec:InclusiveNamespaces'))->setAttribute('PrefixList', 'v4');
        $ref->appendChild($doc->createElementNS(self::NS_DS, 'ds:DigestMethod'))
            ->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $digest = base64_encode(hash('sha256', $body->C14N(true, false, null, ['v4']), true));
        $ref->appendChild($doc->createElementNS(self::NS_DS, 'ds:DigestValue', $digest));

        if (!openssl_sign($si->C14N(true, false, null, ['soapenv', 'v4']), $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new EetException('Podpis selhal: ' . openssl_error_string());
        }
        $sig->appendChild($doc->createElementNS(self::NS_DS, 'ds:SignatureValue', base64_encode($signature)));
        $str = $sig->appendChild($doc->createElementNS(self::NS_DS, 'ds:KeyInfo'))
            ->appendChild($doc->createElementNS(self::NS_WSSE, 'wsse:SecurityTokenReference'));
        $r = $str->appendChild($doc->createElementNS(self::NS_WSSE, 'wsse:Reference'));
        $r->setAttribute('URI', '#X509');
        $r->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');

        return $doc->saveXML();
    }

    /**
     * @param array<string, mixed> $t
     * @return array<string, string>
     */
    private static function normalize(array $t): array
    {
        foreach (['eic_popl', 'id_jednotky', 'id_pokl', 'porad_cis', 'dat_trzby', 'celk_trzba'] as $req) {
            if (!isset($t[$req]) || $t[$req] === '') {
                throw new EetException("Chybí povinná položka $req");
            }
        }
        $out = [];
        foreach (['eic_popl', 'eic_poverujiciho', 'povereni_vice_popl', 'id_jednotky', 'id_pokl', 'porad_cis', 'dat_trzby', 'celk_trzba', 'urceno_cerp_zuct', 'cerp_zuct'] as $k) {
            if (!isset($t[$k]) || $t[$k] === '') {
                continue; // prázdné položky jsou ve zprávě nepřípustné
            }
            $v = $t[$k];
            $out[$k] = match ($k) {
                'dat_trzby' => self::formatDate($v),
                'celk_trzba', 'urceno_cerp_zuct', 'cerp_zuct' => self::formatAmount($v),
                'povereni_vice_popl' => $v ? 'true' : 'false',
                default => (string) $v,
            };
        }
        $patterns = [
            'eic_popl' => '/^CZ\d{8,10}$/', 'eic_poverujiciho' => '/^CZ\d{8,10}$/',
            'id_jednotky' => '/^[1-9]\d{0,8}$/',
            'id_pokl' => '/^[0-9a-zA-Z.,:;\/#\-_ ]{1,20}$/', 'porad_cis' => '/^[0-9a-zA-Z.,:;\/#\-_ ]{1,25}$/',
        ];
        foreach ($patterns as $k => $re) {
            if (isset($out[$k]) && !preg_match($re, $out[$k])) {
                throw new EetException("Neplatný formát $k: '{$out[$k]}'");
            }
        }
        return $out;
    }

    /** Částka v Kč -> "1234.50" (přesně 2 desetinná místa, bez "-0.00"). */
    public static function formatAmount(int|float|string $amount): string
    {
        if (!is_numeric($amount)) {
            throw new EetException("Částka '$amount' není číslo");
        }
        $s = number_format(round((float) $amount, 2), 2, '.', '');
        $s = $s === '-0.00' ? '0.00' : $s;
        if (abs((float) $s) >= 100_000_000) {
            throw new EetException("Částka $s je mimo rozsah");
        }
        return $s;
    }

    /** Datum v pražském čase se zónou, např. 2027-01-09T04:25:28+01:00. Řetězec musí být už v tomto tvaru. */
    public static function formatDate(DateTimeInterface|string $date): string
    {
        if (is_string($date)) {
            if (!preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+\-]\d\d:\d\d)$/', $date)) {
                throw new EetException("Neplatný formát data '$date'");
            }
            return $date;
        }
        return DateTimeImmutable::createFromInterface($date)
            ->setTimezone(new DateTimeZone('Europe/Prague'))
            ->format('Y-m-d\TH:i:sP');
    }

    /** @return array{0: int, 1: string, 2: ?string} */
    private function post(string $xml): array
    {
        $txId = null;
        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $xml,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_HTTPHEADER => ['Content-Type: text/xml; charset=utf-8', 'SOAPAction: "http://fs.gov.cz/eet/OdeslaniTrzby"'],
            CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$txId) {
                if (stripos($line, 'X-Global-Transaction-Id:') === 0) {
                    $txId = trim(substr($line, 24));
                }
                return strlen($line);
            },
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($body === false) {
            // síť / timeout: tržbu je nutné odeslat později (retryable)
            throw new EetException('Spojení s EET selhalo: ' . curl_error($ch), -1);
        }
        return [$status, $body, $txId];
    }

    /** @return array{pok: ?string, test: bool, uuid: string, warnings: array<int, string>, transaction_id: ?string} */
    public static function parseResponse(string $body, int $status, string $uuid, ?string $txId, bool $verifyOnly = false): array
    {
        $doc = new DOMDocument();
        if ($body === '' || !@$doc->loadXML($body)) {
            throw new EetException("Neplatná odpověď EET (HTTP $status)", -1);
        }
        $x = new DOMXPath($doc);
        $x->registerNamespace('e', self::NS_EET);
        $warnings = [];
        foreach ($x->query('//e:Varovani') as $w) {
            $warnings[(int) $w->getAttribute('kod_varov')] = trim($w->textContent);
        }
        $err = $x->query('//e:Chyba')->item(0);
        if ($err) {
            $code = (int) $err->getAttribute('kod');
            if ($code === 0 && $verifyOnly) {
                return ['pok' => null, 'test' => $err->getAttribute('test') === 'true', 'uuid' => $uuid, 'warnings' => $warnings, 'transaction_id' => $txId];
            }
            throw new EetException(trim($err->textContent) . ($txId ? " (tx $txId)" : ''), $code);
        }
        $ok = $x->query('//e:Potvrzeni')->item(0);
        if (!$ok) {
            throw new EetException("Odpověď EET neobsahuje potvrzení ani chybu (HTTP $status)", -1);
        }
        return ['pok' => $ok->getAttribute('pok'), 'test' => $ok->getAttribute('test') === 'true', 'uuid' => $uuid, 'warnings' => $warnings, 'transaction_id' => $txId];
    }

    private static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
