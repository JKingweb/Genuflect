<?php
/*
   Genuflect one-time password library for PHP
    by J. King (http://jkingweb.ca/)
   Licensed under MIT license

   Last revised 2015-09-27
*/

/*
Copyright (c) 2015 J. King

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

namespace genuflect;

function otp_gen($secret, $counter, $digits = 6, $mode = "sha1") {
	// number of digits must be either 6, 7, or 8)
	$digits = min(max($digits,6),8);
	// message to be hashed must be an 8-byte string
	if(is_int($counter) || is_double($counter)) $counter = hex2bin(str_pad(dechex(floor($counter)),16,"0", STR_PAD_LEFT));
	$counter = str_pad($counter, 8, chr(0), STR_PAD_LEFT);
	// hash the counter with the key
	$hash = hash_hmac($mode, $counter, $secret);
	// get the truncation offset)
	$offset = hexdec(substr($hash, -1, 1));
	// truncate the hash to four bytes
	$trunc = substr(hex2bin($hash), $offset, 4);
	// mask the most significant bit
	$trunc[0] = chr(ord($trunc[0]) & 127);
	// convert the binary string to decimal and return the number of least significant digits requested
	$otp = unpack("Nnum", $trunc);
	$otp = substr((string) $otp['num'], -$digits);
	return $otp;
}

function otp_gen_time($step = 30, $epoch = 0, $time = NULL) {
	// step must be at least one second
	$step = (int) max($step, 1);
	// specification says nothing about negative epochs, so I presume they are allowed
	$epoch = (int) $epoch;
	// assume current time if not supplied
	if($time===NULL) $time = time();
	$time = (int) $time;
	return (int) floor(($time - $epoch) / $step);
}

function gen_bytes($count) {
	if (function_exists('random_bytes')) {
		return random_bytes($count);
	} else if (function_exists('openssl_random_pseudo_bytes')) {
		return openssl_random_pseudo_bytes($count);
	} else if (function_exists('mcrypt_create_iv')) {
		return mcrypt_create_iv($count);
	} else if (is_readable('/dev/random')) {
		$f = fopen("/dev/random", "rb");
		$b = fread($f, $count);
		fclose($f);
		return $b;
	} else if (is_readable('/dev/urandom')) {
		$f = fopen("/dev/urandom", "rb");
		$rand = fread($f, $count);
		fclose($f);
		return $rand;
	} else {
		$rand = "";
		for ($a = 0; $a < $count; $a++) {
			$rand .= chr(mt_rand(0, 255));
		} 
    	return $rand;
	}
}

function otp_gen_secret($num_bytes = 20) {
	$num_bytes = max($num_bytes, 15);
	return gen_bytes($num_bytes);
}

class OTP {
	public $type;
	public $secret;
	public $counter;
	public $digits;
	public $mode;
	public $period;
	public $epoch;
	public $pin;
	public $issuer;
	public $account;

	public function generate() {
		switch($this->type) {
			case "totp": return otp_gen($this->secret, otp_gen_time($this->period, $this->epoch), $this->digits, $this->mode);
			case "hotp": return otp_gen($this->secret, $this->counter, $this->digits, $this->mode);
			case "motp": return "stub";
		}
	}
	public function validate($win_after = NULL, $win_before = NULL) {
		switch($this->type) {
			case "totp":
				if($win_after===NULL) $win_after = 2;
				if($win_before===NULL) $win_before = 1;
				break;
			case "hotp":
				if($win_after===NULL) $win_after = 6;
				$win_before = 0;
				break;
			case "motp":
				$win_after = 18;
				$win_before = 18;
		}
		$win_after = abs($win_after);
		$win_before = abs($win_before);
	}
	public function toString() {

	}
	public static function createFromURN($urn) {

	}
}