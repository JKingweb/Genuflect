<?php
namespace Genuflect;

function gen_otp($secret, $counter, $digits = 6, $mode = "sha1") {
	// number of digits must be either 6, 7, or 8)
	$digits = min(max($digits,6),8);
	// message to be hashed must be an 8-byte string
	if(is_int($counter) || is_double($counter)) $counter = hex2bin(str_pad(dechex(floor($counter)),16,"0", STR_PAD_LEFT));
	$counter = str_pad($counter, 8, chr(0), STR_PAD_LEFT);
	// hash the counter with the key
	$hash = hash_hmac($mode, $counter, $secret, false);
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

function gen_time($step = 30, $epoch = 0, $time = NULL) {
	// step must be at least one second
	$step = (int) max($step, 1);
	// specification says nothing about negative epochs, so I presume they are allowed
	$epoch = (int) $epoch;
	// assume current time if not supplied
	if($time===NULL) $time = time();
	$time = (int) $time;
	return (int) floor(($time - $epoch) / $step);
}
