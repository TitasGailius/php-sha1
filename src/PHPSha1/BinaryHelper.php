<?php

namespace PHPSha1;

/**
 * Helper class to make manipulating binary data easier.
 */
class BinaryHelper
{
    /**
     * Returns string representation as string of binary symbols.
     *
     * @param  string $string
     * @return string
     */
    public static function strbin(string $string) : string
    {
        $resultString = '';

        foreach (str_split($string) as $character) {
            $resultString .= sprintf('%08b', ord($character));
        }

        return $resultString;
    }

    /**
     * Returns string representation as integer.
     *
     * @param  string $string
     * @return int
     */
    public static function strdec(string $string) : int
    {
        return bindec(self::strbin($string));
    }

    /**
     * Returs decimal number as string of binary symbols.
     *
     * @param  int    $integer
     * @return string
     */
    public static function decbin(int $integer, int $length = 32) : string
    {
        $binary = decbin($integer);

        while (strlen($binary) % $length !== 0) {
            $binary = '0' . $binary;
        }

        return $binary;
    }

    /**
     * Returns string's length in bits.
     *
     * @param  string $string
     * @return int
     */
    public static function strlen(string $string) : int
    {
        return strlen($string) * 8;
    }

    /**
     * Rotate provided decimal's bit to the left by specified positions
     *
     * @param  int     $data
     * @param  integer $positions
     * @return integer
     */
    public static function decRotateLeft(int $data, int $positions = 1) : int
    {
        return ($data << $positions) | ($data >> (32 - $positions));
    }
}
