<?php
namespace Genuflect;

function gen_otp($K, $C, $digits = 6, $mode = "sha1") {
	// number of digits must be either 6, 7, or 8)
	$digits = min(max($digits,6),8);
	// message to be hashed must be an 8-byte string
	$C = str_pad($C, 8, chr(0), STR_PAD_LEFT);
	// hash the counter with the key
	$msg = hash_hmac($mode, $C, $K, false);
	// get the truncation offset)
	$offset = hexdec(substr($msg, -1, 1));
	// truncate the hash to four bytes
	$trunc = substr(hex2bin($msg), $offset, 4);
	// mask the most significant bit
	$trunc[0] = chr(ord($trunc[0]) & 127);
	// convert the binary string to decimal and return the number of least significant digits requested
	$otp = unpack("Nnum", $trunc);
	$otp = substr((string) $otp['num'], -$digits);
	return $otp;
}
