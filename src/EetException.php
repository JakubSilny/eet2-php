<?php

declare(strict_types=1);

namespace Eet2;

final class EetException extends \RuntimeException
{
    /** Podpis potvrzení nesedí - POK nelze věřit, tržbu poslat znovu. */
    public const SIGNATURE_INVALID = -900;

    /**
     * Dočasná chyba (síť, výpadek EET, neověřitelné potvrzení): tržbu uložit a odeslat znovu
     * se send($trzba, firstAttempt: false). Ostatní kódy jsou chyby dat nebo certifikátu.
     */
    public function isRetryable(): bool
    {
        return in_array($this->getCode(), [-1, 8, self::SIGNATURE_INVALID], true);
    }
}
