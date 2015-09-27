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

namespace Genuflect;

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

