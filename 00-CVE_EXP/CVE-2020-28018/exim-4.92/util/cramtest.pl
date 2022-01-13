#!/usr/bin/perl

# This script is contributed by Vadim Vygonets to aid in debugging CRAM-MD5
# authentication.

# A patch was contributed by Jon Warbrick to upgrade it to use the Digest::MD5
# module instead of the deprecated MD5 module.

# The script prompts for three data values: a user name, a password, and the
# challenge as sent out by an SMTP server. The challenge is a base-64 string.
# It should be copied (cut-and-pasted) literally as the third data item. The
# output of the program is the base-64 string that is to be returned as the
# response to the challenge. Using the example in RFC 2195:
#
# User: tim
# Password: tanstaaftanstaaf
# Challenge: PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
# dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
#
# The last line is what you you would send back to the server.


# Copyright (c) 2002
#       Vadim Vygonets <vadik-exim@vygo.net>.  All rights reserved.
# Public domain is OK with me.

BEGIN { pop @INC if $INC[-1] eq '.' };

use MIME::Base64;
use Digest::MD5;

print "User: ";
chop($user = <>);
print "Password: ";
chop($passwd = <>);
print "Challenge: ";
chop($chal = <>);
$chal =~ s/^334 //;

$context = new Digest::MD5;
if (length($passwd) > 64) {
        $context->add($passwd);
        $passwd = $context->digest();
        $context->reset();
}

@passwd = unpack("C*", pack("a64", $passwd));
for ($i = 0; $i < 64; $i++) {
        $pass_ipad[$i] = $passwd[$i] ^ 0x36;
        $pass_opad[$i] = $passwd[$i] ^ 0x5C;
}
$context->add(pack("C64", @pass_ipad), decode_base64($chal));
$digest = $context->digest();
$context->reset();
$context->add(pack("C64", @pass_opad), $digest);
$digest = $context->digest();

print encode_base64($user . " " . unpack("H*", $digest));

# End
