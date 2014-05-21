<?php
/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Two factor authentication module.
 *
 * Revised version of
 * http://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/
 *
 */
class TwoFactor {
    const keyRegeneration = 30; // Interval between key regeneration
    const otpLength = 6;        // Length of the Token generated

    /**
     * Generates a 16 digit secret key in base32 format
     * @return string
     * */

    public static function generateKey($length = 16) {
        $key = "";

        for ($i = 0; $i < $length; $i++) {
            $key .= Base32::getRandom();
        }

        return $key;
    }

    /**
     * Returns the current Unix Timestamp devided by the keyRegeneration
     * period.
     * @return integer
     * */
    public static function getTimestamp() {
        return floor(microtime(true) / self::keyRegeneration);
    }

    /**
     * Return the <img> string for a QR code scannable by the Google Authenticator app
     * @param type $username
     * @param type $userkey
     * @return string
     */
    public static function getQrCode($username, $userkey) {
        return '<img src="https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/' . $username . '?secret=' . $userkey . '" />';
    }

    /**
     * Verifys a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string $b32seed
     * @param string $key - User specified key
     * @param integer $drift
     * @return boolean
     * */
    public static function verifyKey($b32seed, $key, $drift = 4) {
        $timestamp = self::getTimestamp();
        $binarySeed = Base32::decode($b32seed);

        for ($ts = $timestamp - $drift; $ts <= $timestamp + $drift; $ts++) {
            if (self::getSecret($binarySeed, $ts) == $key) {
                return TRUE;
            }
        }

        return FALSE;
    }


    /**
     * Takes the secret key and the timestamp and returns the one time password.
     *
     * @param binary $key - Secret key in binary form.
     * @param integer $counter - Timestamp as returned by gettimestamp.
     * @return string
     * */
    public static function getSecret($key, $counter) {
        if (strlen($key) < 8) {
            throw new Exception('Secret key is too short. Must be at least 16 base 32 characters');
        }

        $bin_counter = pack('N*', 0) . pack('N*', $counter);  // Counter must be 64-bit int
        $hash = hash_hmac('sha1', $bin_counter, $key, true);

        return str_pad(self::oathTruncate($hash), self::otpLength, '0', STR_PAD_LEFT);
    }

    /**
     * Extracts the OTP from the SHA1 hash.
     * @param binary $hash
     * @return integer
     * */
    public static function oathTruncate($hash) {
        $offset = ord($hash[19]) & 0xf;

        return (
                ((ord($hash[$offset + 0]) & 0x7f) << 24 ) |
                ((ord($hash[$offset + 1]) & 0xff) << 16 ) |
                ((ord($hash[$offset + 2]) & 0xff) << 8 ) |
                (ord($hash[$offset + 3]) & 0xff)
                ) % pow(10, self::otpLength);
    }

}