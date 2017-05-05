<?php

namespace PHPSha1;

/**
 * Pure PHP implementation of SHA1 hash function.
 */
class Sha1
{
    /**
     * Current instance of the Sha1
     *
     * @var Sha1
     */
    protected static $instance;

    /**
     * Predefined SHA-1 specific starting hash values.
     *
     * @var array
     */
    protected $hashValues = [];

    /**
     * Values used in between hash calculations.
     *
     * @var array
     */
    protected $intermediateValues = [];

    /**
     * Message that is being formatted and hashed
     *
     * @var string
     */
    protected $message;

    /**
     * Hashes provided message with Sha1.
     *
     * @param  string $message
     * @return string
     */
    public static function hash($message)
    {
        $instance = self::instance();

        $instance->message = $message;

        $instance->preProcess();
        $instance->setHashValues();

        return $instance->calculateHashValue();
    }

    /**
     * Return current instance of the Sha1
     *
     * @return Sha1
     */
    protected static function instance()
    {
        if (!static::$instance) {
            static::$instance = new self;
        }

        return static::$instance;
    }

    /**
     * Format message for SHA1 specific formate before calculating hash value.
     */
    protected function preProcess()
    {
        /**
         * Store original message's length (in bits) because
         * this will be needed for padding the message later on.
         */
        $originalLength = BinaryHelper::strlen($this->message);

        /*
         * Strings in PHP are initially stored as
         * binary values so we can append 0x80 right away.
         */
        $this->message .= chr(128);

        /*
         * Append '0' bit to the end of the message until
         * it's length divided by 512 has the reminder of 448.
         */
        while (BinaryHelper::strlen($this->message) % 512 !== 448) {
            $this->message .= chr(0);
        }

        /*
         * Convert original message's length to 64 bit binary representation
         * and append it to the end of the message as an actual binary data
         */
        foreach (str_split(sprintf('%064b', $originalLength), 8) as $binaryNumber) {
            $this->message .= chr(bindec($binaryNumber));
        }
    }

    /**
     * Set initial hash values
     */
    protected function setHashValues()
    {
        $this->hashValues = [
            'h0' => 0x67452301,
            'h1' => 0xEFCDAB89,
            'h2' => 0x98BADCFE,
            'h3' => 0x10325476,
            'h4' => 0xC3D2E1F0,
        ];

        $this->intermediateValues = [
            'a' => $this->hashValues['h0'],
            'b' => $this->hashValues['h1'],
            'c' => $this->hashValues['h2'],
            'd' => $this->hashValues['h3'],
            'e' => $this->hashValues['h4'],
        ];
    }

    /**
     * Start calculation process of the hash value for current message.
     *
     * @return string
     */
    protected function calculateHashValue() : string
    {
        /*
         * Split message into [512-bit Chunks]
         * and apply calculations for each chunk.
         */
        foreach (str_split($this->message, 64) as $chunk) {

            /*
             * Apply SHA1 specific calculations
             */
            $this->applyChunkCalculations($chunk);

            /*
             * Append calculated intermediate values to hash values
             */
            $this->hashValues['h0'] = ($this->hashValues['h0'] + $this->intermediateValues['a']) & 0xffffffff;
            $this->hashValues['h1'] = ($this->hashValues['h1'] + $this->intermediateValues['b']) & 0xffffffff;
            $this->hashValues['h2'] = ($this->hashValues['h2'] + $this->intermediateValues['c']) & 0xffffffff;
            $this->hashValues['h3'] = ($this->hashValues['h3'] + $this->intermediateValues['d']) & 0xffffffff;
            $this->hashValues['h4'] = ($this->hashValues['h4'] + $this->intermediateValues['e']) & 0xffffffff;
        }

        /*
         * Join calculated hash values and return it as final hash value
         */
        return sprintf('%08x%08x%08x%08x%08x', $this->hashValues['h0'], $this->hashValues['h1'], $this->hashValues['h2'], $this->hashValues['h3'], $this->hashValues['h4']);
    }

    /**
     * Apply intermediate values calculation for each group of chunk.
     *
     * @param string $chunk
     */
    protected function applyChunkCalculations(string $chunk)
    {
        /*
         * Split each chunk into [4 Groups] of 20 words
         * and apply calculations for intermediate values.
         */
        foreach (array_chunk($this->generateWordsForChunk($chunk), 20) as $group => $words) {
            $this->intermediateValuesForWords($words, $group);
        }
    }

    /**
     * Generate required words for given 512-bit chunk.
     *
     * @param  sting $chunk
     * @return array
     */
    protected function generateWordsForChunk(string $chunk) : array
    {
        /**
         * Split a chunk into 16 32-bit (4 characters) words
         * and convert these words into string of binary symbols.
         */
        $words = array_map(function ($word) {
            return BinaryHelper::strdec($word);
        }, str_split($chunk, 4));

        /*
         * Extnend current 16 words into 80
         * words by applying spedific SHA1 logic
         */
        for ($i = 16; $i < 80; ++$i) {

            /**
             * XOR words indexed as [i - 3] [i - 8] [i - 14] [i - 16].
             */
            $xored = $words[$i - 3] ^ $words[$i - 8] ^ $words[$i - 14] ^ $words[$i - 16];

            /*
             * Rotate xored result by 1 bit to the left
             * and save it as a 32-bit unsigned integer
             */
            $words[$i] = BinaryHelper::decRotateLeft($xored, 1) & 0xffffffff;
        }

        return $words;
    }

    /**
     * For each word in a group apply specific calculations for intermediate values.
     *
     * @param array $words
     * @param int   $group
     */
    protected function intermediateValuesForWords(array $words, int $group)
    {
        foreach ($words as $word) {

            /**
             * Group specific calculations for current word.
             */
            $temporary = BinaryHelper::decRotateLeft($this->intermediateValues['a'], 5) + $this->applyHashFunction($group) + $this->intermediateValues['e'] + $this->kValue($group) + ($word) & 0xffffffff;

            /*
             * General SHA1 calculations
             */
            $this->intermediateValues['e'] = $this->intermediateValues['d'];
            $this->intermediateValues['d'] = $this->intermediateValues['c'];
            $this->intermediateValues['c'] = BinaryHelper::decRotateLeft($this->intermediateValues['b'], 30);
            $this->intermediateValues['b'] = $this->intermediateValues['a'];
            $this->intermediateValues['a'] = $temporary;
        }
    }

    /**
     * Apply calculations for specified group of words per chunk.
     *
     * @param int $group
     */
    protected function applyHashFunction(int $group)
    {
        switch ($group) {
            case 0: return ($this->intermediateValues['b'] & $this->intermediateValues['c']) ^ (~$this->intermediateValues['b'] & $this->intermediateValues['d']);
            case 1: return $this->intermediateValues['b'] ^ $this->intermediateValues['c'] ^ $this->intermediateValues['d'];
            case 2: return ($this->intermediateValues['b'] & $this->intermediateValues['c']) ^ ($this->intermediateValues['b'] & $this->intermediateValues['d']) ^ ($this->intermediateValues['c'] & $this->intermediateValues['d']);
            case 3: return $this->applyHashFunction(1);
        }
    }

    /**
     * Return [K] value depending on the current group.
     *
     * @param  int $group
     * @return int
     */
    protected function kValue(int $group) : int
    {
        switch ($group) {
            case 0: return 0x5a827999;
            case 1: return 0x6ed9eba1;
            case 2: return 0x8f1bbcdc;
            case 3: return 0xca62c1d6;
        }

        throw new Exception("Unexpected group '{$group}'");
    }
}
