# EET 2.0 klient pro PHP

Odesílání tržeb do **EET 2.0** (evidence tržeb od 1. 1. 2027, rozhraní v4). Řeší za vás SOAP, podpis WS-Security (XML-DSig, exc-c14n, RSA-SHA256), formáty položek a zpracování odpovědí.

- Bez závislostí: stačí `ext-dom`, `ext-openssl` a `ext-curl`, PHP 8.1+
- Otestováno proti státnímu Playgroundu (`pg.trzbyeet.gov.cz`)
- Načte certifikáty z DIS+ (`.p12`), včetně starého šifrování RC2, které OpenSSL 3 samo neotevře

```bash
composer require jakubsilny/eet2
```

Web a dokumentace: **https://jakubsilny.github.io/eet2-php/**

> **EET 2.0 Pro** přidává frontu s automatickým doposíláním při výpadku, automatickou obnovu pokladního certifikátu, CLI a integraci pro Laravel a Nette. [Více na webu](https://jakubsilny.github.io/eet2-php/#pro)

## Použití

```php
use Eet2\{Client, EetException};

$eet = Client::fromP12('pokladni-certifikat.p12', 'heslo', Client::PLAYGROUND);

try {
    $r = $eet->send([
        'eic_popl'    => 'CZ683555118',     // EIČ poplatníka
        'id_jednotky' => 101,               // číslo evidenční jednotky z DIS+
        'id_pokl'     => 'POKLADNA-1',
        'porad_cis'   => '2027/000123',     // číslo účtenky
        'dat_trzby'   => new DateTimeImmutable(),
        'celk_trzba'  => 249.90,
    ]);
    echo $r['pok'];                          // potvrzovací kód (POK)
} catch (EetException $e) {
    if ($e->isRetryable()) {
        // výpadek sítě nebo EET: uložit a poslat později se send($trzba, firstAttempt: false)
    } else {
        // chyba dat nebo certifikátu: $e->getCode() = kód chyby EET
    }
}
```

Nepovinné položky: `eic_poverujiciho`, `povereni_vice_popl`, `urceno_cerp_zuct`, `cerp_zuct`.
Ověřovací mód (spojení se otestuje, tržba se neeviduje): `$eet->send($trzba, verifyOnly: true)`.

Návratová hodnota: `pok`, `test` (true = neprodukční prostředí), `uuid`, `warnings` (kód => text), `transaction_id` (hlavička `X-Global-Transaction-Id` pro dohledání u finanční správy).

## Testy

```bash
composer test        # offline: kanonizace podle oficiálního vzoru, XSD, podpis, formáty
composer test-live   # živě proti Playgroundu s veřejnými testovacími certifikáty
```

## Produkce

Použijte `Client::PRODUCTION` a svůj pokladní certifikát. Produkční certifikáty se generují v DIS+ od 1. 11. 2026.
Každé potvrzení se ověřuje (podpis GFŘ přes I.CA). Když ověření selže, `EetException::SIGNATURE_INVALID` se chová jako dočasná chyba.

## Licence

MIT. Knihovna není oficiálním produktem Finanční správy ČR a za správnost evidence odpovídá poplatník.
