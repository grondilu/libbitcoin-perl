#!/usr/bin/perl
package Bitcoin::Script::Stack;
use strict;
use warnings;

=begin comment

my (@S, @alt_S);
sub check_size { die "stack is too small" if @S < shift }
sub Pop { pop @S // die "stack is too small" }
sub Push { push @S, @_ }

sub OP_TOALTSTACK   { push @alt_S, $S[$#S] // die "empty stack" }
sub OP_FROMALTSTACK { Push pop @alt_S // die "empty alt stack" }
sub OP_DROP  { Pop }
sub OP_2DROP { Pop, Pop }
sub OP_DUP   { check_size 1; Push $S[$#S] }
sub OP_2DUP  { check_size 2; Push @S[$#S-1,$#S] }
sub OP_3DUP  { check_size 3; Push @S[$#S-2 .. $#S] }
sub OP_2OVER { check_size 4; splice @S, -4, 0, @S[$#S-1,$#S] }
sub OP_2ROT  { check_size 6; Push splice @S, -6, 2 }
sub OP_2SWAP { check_size 4; Push splice @S, -4, 2 }
sub OP_IFDUP { check_size 1; Push $S[$#S] if $S[$#S] }
sub OP_DEPTH { Push scalar @S }
sub OP_NIP   { check_size 2; splice @S, -2, 1 }
sub OP_OVER  { check_size 2; Push $S[$#S-1] }
sub OP_PICK  { check_size my $n = shift;  Push $S[$#S - $n + 1] }
sub OP_ROLL  { check_size my $n = shift;  Push $S[$#S - $n + 1]; splice @S, -$n, 1 }
sub OP_ROT   { check_size 3; Push splice @S, -3, 1 }
sub OP_SWAP  { OP_NIP OP_ROT OP_DUP }
sub OP_TUCK  { OP_ROT OP_ROT OP_DUP }

sub OP_0	{ Push 0 }
sub OP_1NEGATE  { Push -1 }
sub OP_ADD      { Push OP_DROP() + OP_DROP() }
sub OP_MUL      { Push OP_DROP() * OP_DROP() }
sub OP_DIV      { use integer; Push OP_DROP() / OP_DROP() }
sub OP_MOD      { Push OP_DROP() % OP_DROP() }
sub OP_LSHIFT   { Push OP_DROP() << OP_DROP() }
sub OP_RSHIFT   { Push OP_DROP() >> OP_DROP() }
sub OP_BOOLAND  { Push OP_DROP ? OP_DROP() : (OP_DROP, 0) }  # using ternary to avoid laziness
sub OP_BOOLOR   { Push OP_DROP ? (OP_DROP, 1) : OP_DROP }  # using ternary to avoid laziness
sub OP_NUMEQUAL { Push OP_DROP() == OP_DROP() }
sub OP_NUMEQUALVERIFY { OP_NUMEQUAL; die "OP_NUMEQUALVERIFY" unless OP_DROP }
sub OP_LESSTHAN { Push OP_DROP < OP_DROP }
sub OP_GREATERTHAN { Push OP_DROP > OP_DROP }
sub OP_GREATERTHANOREQUAL { Push OP_DROP >= OP_DROP }
sub OP_MIN      { (OP_DROP OP_LESSTHAN OP_2DUP) ? OP_NIP : OP_DROP }
sub OP_MAX      { (OP_DROP OP_LESSTHAN OP_2DUP) ? OP_DROP : OP_NIP }

sub OP_WITHIN   { OP_BOOLAND OP_LESSTHAN OP_ROT OP_ROT OP_LESSTHAN OP_OVER OP_SWAP OP_ROT }

sub OP_RIPEMD160 { Push qx/perl -e 'print pack "b*", '@{[unpack 'b*', OP_DROP]}' | openssl dgst -rmd160 -binary/ }
sub OP_SHA1      { use Digest::SHA qw(sha1);   Push sha1 OP_DROP }
sub OP_SHA256    { use Digest::SHA qw(sha256); Push sha256 OP_DROP }
sub OP_HASH160   { use Bitcoin; Push Bitcoin::hash160 OP_DROP }
sub OP_HASH256   { use Bitcoin; Push Bitcoin::hash    OP_DROP }

sub OP_1ADD        { OP_ADD OP_1 }
sub OP_1SUB        { OP_ADD OP_1NEGATE }
sub OP_2MUL        { Push OP_DROP << 1 }
sub OP_2DIV        { Push OP_DROP >> 1 }
sub OP_NEGATE      { OP_MUL OP_1NEGATE }
sub OP_ABS         { Push abs OP_DROP }
sub OP_NOT         { Push not OP_DROP }
sub OP_0NOTEQUAL   { Push OP_DROP != 0 }

sub OP_CAT           { check_size 2; Push OP_DROP() . OP_DROP }
sub OP_SUBSTR        { check_size 3; OP_SWAP; OP_ROT; Push substr OP_DROP, OP_DROP, OP_DROP }
sub OP_LEFT          { check_size 2; OP_SUBSTR OP_SWAP OP_0 }
sub OP_RIGHT         { check_size 2; OP_SUBSTR OP_SWAP OP_NEGATE OP_DUP }
sub OP_SIZE          { check_size 1; OP_DUP; Push scalar map undef, OP_DROP =~ /./mgs }
sub OP_INVERT        { check_size 1; Push ~OP_DROP }
sub OP_AND           { check_size 2; Push OP_DROP() & OP_DROP }
sub OP_OR            { check_size 2; Push OP_DROP() | OP_DROP }
sub OP_XOR           { check_size 2; Push OP_DROP() ^ OP_DROP }
sub OP_EQUAL         { check_size 2; Push OP_DROP() eq OP_DROP }
sub OP_EQUALVERIFY   { die "OP_EQUALVERIFY" unless OP_DROP OP_EQUAL }

use constant CODE => {

    # {{{ Constants
    OP_0 => 0, OP_FALSE	=> 0,   # An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)
    #  1, 2, ..., 75            # The next opcode bytes is data to be pushed onto the stack
    OP_PUSHDATA1 => 76,         # The next byte      contains the number of bytes to be pushed onto the stack.
    OP_PUSHDATA2 => 77,         # The next two bytes contain  the number of bytes to be pushed onto the stack.
    OP_PUSHDATA4 => 78,         # The next four byte contain  the number of bytes to be pushed onto the stack.
    OP_1NEGATE => 79,           # The number -1 is pushed onto the stack.
    OP_1 => 81, OP_TRUE	=> 81,  # The number  1 is pushed onto the stack.
    OP_2 => 82,                 # The number in the word name (2-16) is pushed onto the stack.
    OP_3 => 83,
    OP_4 => 84,
    OP_5 => 85,
    OP_6 => 86,
    OP_7 => 87,
    OP_8 => 88,
    OP_9 => 89,
    OP_10 => 90,
    OP_11 => 91,
    OP_12 => 92,
    OP_13 => 93,
    OP_14 => 94,
    OP_15 => 95,
    OP_16 => 96,
    # }}}
    # {{{ Flow control
    OP_NOP	=> 97,		# Does nothing.
    OP_IF	=> 99,  	# If the top stack value is 1, the statements are executed. The top stack value is removed.
    OP_NOTIF	=> 100, 	# If the top stack value is 0, the statements are executed. The top stack value is removed.
    OP_ELSE	=> 103, 	# If the preceding OP_IF or OP_NOTIF was not executed then these statements are.
    OP_ENDIF	=> 104, 	# Ends an if/else block.
    OP_VERIFY	=> 105, 	# Marks transaction as invalid if top stack value is not true.
                                # True is removed, but false is not.
    OP_RETURN	=> 106, 	# Marks transaction as invalid.
    # }}}
    # {{{ Stack
    OP_TOALTSTACK	=> 107,  # ( x1 -- (alt)x1 )        Puts the input onto the top of the alt stack. Removes it from the main stack.
    OP_FROMALTSTACK	=> 108,  # ( (alt)x1 -- x1 )             Puts the input onto the top of the main stack. Removes it from the alt stack.
    OP_IFDUP        	=> 115,  # ( x -- x / x x )        If the input is true or false, duplicate it.
    OP_DEPTH        	=> 116,  # ( -- <Stack size> )   Puts the number of stack items onto the stack.
    OP_DROP         	=> 117,  # ( x -- )         Removes the top stack item.
    OP_DUP          	=> 118,  # ( x -- x x )     Duplicates the top stack item.
    OP_NIP          	=> 119,  # ( x1 x2 --  x2 )             Removes the second-to-top stack item.
    OP_OVER         	=> 120,  # ( x1 x2 --  x1 x2 x1 )      Copies the second-to-top stack item to the top.
    OP_PICK         	=> 121,  # ( xn ... x2 x1 x0 <n> -- xn ... x2 x1 x0 xn )	The item n back in the stack is copied to the top.
    OP_ROLL         	=> 122,  # ( xn ... x2 x1 x0 <n> -- ... x2 x1 x0 xn )      The item n back in the stack is moved to the top.
    OP_ROT          	=> 123,  # ( x1 x2 x3 -- x2 x3 x1 )       The top three items on the stack are rotated to the left.
    OP_SWAP         	=> 124,  # ( x1 x2 -- x2 x1 )          The top two items on the stack are swapped.
    OP_TUCK         	=> 125,  # ( x1 x2 -- x2 x1 x2 )       The item at the top of the stack is copied and inserted before the second-to-top item.
    OP_2DROP        	=> 109,  # ( x1 x2 -- )         Removes the top two stack items.
    OP_2DUP         	=> 110,  # ( x1 x2 -- x1 x2 x1 x2 )    Duplicates the top two stack items.
    OP_3DUP         	=> 111,  # ( x1 x2 x3 -- x1 x2 x3 x1 x2 x3 ) Duplicates the top three stack items.
    OP_2OVER        	=> 112,  # ( x1 x2 x3 x4  -- x1 x2 x3 x4 x1 x2 ) Copies the pair of items two spaces back in the stack to the front.
    OP_2ROT         	=> 113,  # ( x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2 ) The fifth and sixth items back are moved to the top of the stack.
    OP_2SWAP        	=> 114,  # ( x1 x2 x3 x4  -- x3 x4 x1 x2 )    Swaps the top two pairs of items.
    # }}}
    # {{{ Splice
    OP_CAT    	=> 126,  #   x1 x2         out     Concatenates two strings. Currently disabled.
    OP_SUBSTR 	=> 127,  #   in begin size out     Returns a section of a string. Currently disabled.
    OP_LEFT   	=> 128,  #   in size       out     Keeps only characters left of the specified point in a string. Currently disabled.
    OP_RIGHT  	=> 129,  #   in size       out     Keeps only characters right of the specified point in a string. Currently disabled.
    OP_SIZE   	=> 130,  #   in            in size Returns the length of the input string.
    # }}}
    # {{{ Bitwise logic
    OP_INVERT      	=> 131,  #   in    out          Flips all of the bits in the input. Currently disabled.
    OP_AND         	=> 132,  #   x1 x2 out          Boolean and between each bit in the inputs. Currently disabled.
    OP_OR          	=> 133,  #   x1 x2 out          Boolean or between each bit in the inputs. Currently disabled.
    OP_XOR         	=> 134,  #   x1 x2 out          Boolean exclusive or between each bit in the inputs. Currently disabled.
    OP_EQUAL       	=> 135,  #   x1 x2 True / false Returns 1 if the inputs are exactly equal, 0 otherwise.
    OP_EQUALVERIFY 	=> 136,  #   x1 x2 True / false Same as OP_EQUAL, but runs OP_VERIFY afterward.
    # }}}
    # {{{ Arithmetic
    OP_1ADD               	=> 139,   #   in        out    1 is added to the input.
    OP_1SUB               	=> 140,   #   in        out    1 is subtracted from the input.
    OP_2MUL               	=> 141,   #   in        out    The input is multiplied by 2. Currently disabled.
    OP_2DIV               	=> 142,   #   in        out    The input is divided by 2. Currently disabled.
    OP_NEGATE             	=> 143,   #   in        out    The sign of the input is flipped.
    OP_ABS                	=> 144,   #   in        out    The input is made positive.
    OP_NOT                	=> 145,   #   in        out    If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
    OP_0NOTEQUAL          	=> 146,   #   in        out    Returns 1 if the input is 0. 0 otherwise.
    OP_ADD                	=> 147,   #   a b       out    a is added to b.
    OP_SUB                	=> 148,   #   a b       out    b is subtracted from a.
    OP_MUL                	=> 149,   #   a b       out    a is multiplied by b. Currently disabled.
    OP_DIV                	=> 150,   #   a b       out    a is divided by b. Currently disabled.
    OP_MOD                	=> 151,   #   a b       out    Returns the remainder after dividing a by b. Currently disabled.
    OP_LSHIFT             	=> 152,   #   a b       out    Shifts a left b bits, preserving sign. Currently disabled.
    OP_RSHIFT             	=> 153,   #   a b       out    Shifts a right b bits, preserving sign. Currently disabled.
    OP_BOOLAND            	=> 154,   #   a b       out    If both a and b are not 0, the output is 1. Otherwise 0.
    OP_BOOLOR             	=> 155,   #   a b       out    If a or b is not 0, the output is 1. Otherwise 0.
    OP_NUMEQUAL           	=> 156,   #   a b       out    Returns 1 if the numbers are equal, 0 otherwise.
    OP_NUMEQUALVERIFY     	=> 157,   #   a b       out    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
    OP_NUMNOTEQUAL        	=> 158,   #   a b       out    Returns 1 if the numbers are not equal, 0 otherwise.
    OP_LESSTHAN           	=> 159,   #   a b       out    Returns 1 if a is less than b, 0 otherwise.
    OP_GREATERTHAN        	=> 160,   #   a b       out    Returns 1 if a is greater than b, 0 otherwise.
    OP_LESSTHANOREQUAL    	=> 161,   #   a b       out    Returns 1 if a is less than or equal to b, 0 otherwise.
    OP_GREATERTHANOREQUAL 	=> 162,   #   a b       out    Returns 1 if a is greater than or equal to b, 0 otherwise.
    OP_MIN                	=> 163,   #   a b       out    Returns the smaller of a and b.
    OP_MAX                	=> 164,   #   a b       out    Returns the larger of a and b.
    OP_WITHIN             	=> 165,   #   x min max out    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
    # }}}
    # {{{ Crypto
    OP_RIPEMD160           	=> 166,  #  ( in -- hash )    The input is hashed using RIPEMD-160.
    OP_SHA1                	=> 167,  #  ( in -- hash )    The input is hashed using SHA-1.
    OP_SHA256              	=> 168,  #  ( in -- hash )    The input is hashed using SHA-256.
    OP_HASH160             	=> 169,  #  ( in -- hash )    The input is hashed twice: first with SHA-256, and then with RIPEMD-160.
    OP_HASH256             	=> 170,  #  ( in -- hash )    The input is hashed two times with SHA-256.
    OP_CODESEPARATOR       	=> 171,  #  ( -- )
					 # All of the signature checking words will only match signatures to the data
					 # after the most recently-executed OP_CODESEPARATOR.  The entire transaction's
					 # outputs, inputs, and script (from the most recently-executed
					 # OP_CODESEPARATOR to the end) are hashed.
    OP_CHECKSIG            	=> 172,  #  ( sig pubkey -- True / false )
					 # The signature used by OP_CHECKSIG must be a valid signature for this hash
					 # and public key. If it is, 1 is returned, 0 otherwise.
    OP_CHECKSIGVERIFY      	=> 173,  #   ( sig pubkey  -- True / false ) Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.  
    OP_CHECKMULTISIG       	=> 174,  #   (
				     #      x sig1 sig2 ...  <number of signatures> pub1 pub2 <number of public keys>
				     #      -- True / False  
				     #   )  
				     #   For each signature and public key pair,
				     #   OP_CHECKSIG is executed.  If more public keys than signatures are
				     #   listed, some key/sig pairscan fail. All
				     #   signatures need to match a public key. If
				     #   all signatures are
				     #   valid, 1 is returned, 0 otherwise. Due to
				     #   a bug, one extra unused value is removed
				     #   from the stack. 
    OP_CHECKMULTISIGVERIFY 	=> 175,  #   ( 
				     #      x sig1 sig2 ...  <number of signatures> pub1 pub2 <number of public keys>
				     #      -- True / False  
				     #   )
				     #   Same as OP_CHECKMULTISIG, but OP_VERIFY is
				     #   executed afterward. 
    # }}}
    # {{{ Pseudo-words
    OP_PUBKEYHASH    	=> 253,  #   Represents a public key hashed with OP_HASH160.
    OP_PUBKEY        	=> 254,  #   Represents a public key compatible with OP_CHECKSIG.
    OP_INVALIDOPCODE 	=> 255,  #   Matches any opcode that is not yet assigned.
    # }}}
    # {{{ Reserved words
    OP_RESERVED      	=>  80,   # Transaction is invalid
    OP_VER           	=>  98,   # Transaction is invalid
    OP_VERIF         	=> 101,   # Transaction is invalid
    OP_VERNOTIF      	=> 102,   # Transaction is invalid
    OP_RESERVED1     	=> 137,   # Transaction is invalid
    OP_RESERVED2     	=> 138,   # Transaction is invalid
    OP_NOP1 => 176,                   # The word is ignored.
    OP_NOP2 => 177,
    OP_NOP3 => 178,
    OP_NOP4 => 179,
    OP_NOP5 => 180,
    OP_NOP6 => 181,
    OP_NOP7 => 182,
    OP_NOP8 => 183,
    OP_NOP9 => 184,
    OP_NOP10 => 185,
    # }}}

};                              
=end comment

=cut
                                
package Bitcoin::Script;
use strict;
use warnings;

sub new {
    my $class = shift; do {...} if ref $class;
    my $arg = shift; do {...} if ref $arg;
    my $this = bless { code => unpack 'H*', $arg }, $class;
    $this->decode;
}
sub binary_code { my $_ = shift; die 'empty code' if $_->{code} eq ''; pack 'H*', $_->{code}  }
sub first_char  { my $_ = shift; ord substr $_->binary_code, 0, 1 }
sub data_length {
    my $this = shift; do {...} unless ref $this;
    my $first_char = $this->first_char;
    $first_char  < 76 ? $first_char :
    $first_char == 76 ? unpack 's>', substr $this->binary_code, 1, 1 :
    $first_char == 77 ? unpack 's>', substr $this->binary_code, 1, 2 :
    $first_char == 78 ? unpack 's>', substr $this->binary_code, 1, 4 :
    0;
}
sub data_offset {
    my $this = shift; do {...} unless ref $this;
    my $first_char = $this->first_char;
    $first_char  < 76 ? 1 :
    $first_char == 76 ? 2 :
    $first_char == 77 ? 3 :
    $first_char == 78 ? 5 :
    0;
}


sub decode {
    my $this = shift; do {...} unless ref $this;
    return if $this->{code} eq '';
    my @decode;
    my $binary_code = $this->binary_code;
    my $first_char  = $this->first_char;
    my $data_length = $this->data_length;
    my $data_offset = $this->data_offset;
    if ($first_char < 79 and $first_char > 0) {
	push @decode, (ref($this).'::PushData')->new(substr $binary_code, 0, $data_offset + $data_length);
    }
    else {
	push @decode, (ref($this).'::OP')->new(chr $first_char);
	$data_length = 1;
    }
    my $remain = substr $binary_code, $data_offset + $data_length;
    push @decode, @{ref($this)->new($remain)->{decode} // []} unless $remain eq '';
    $this->{decode} = [ @decode ] if @decode;
    return $this;
}

package Bitcoin::Script::OP;
our @ISA = qw(Bitcoin::Script);
sub decode {
    my $this = shift; do {...} unless ref $this;
    return if $this->{code} eq '';
    $this->{value} = hex $this->{code};
    return $this;
}

package Bitcoin::Script::PushData;
our @ISA = qw(Bitcoin::Script);
use MIME::QuotedPrint;
sub decode {
    my $this = shift; do {...} unless ref $this;
    return if $this->{code} eq '';
    my $first_char = $this->first_char;
    my $data = substr $this->binary_code, $this->data_offset;
    $this->{data}  = encode_qp $data;
    if ($data =~ /\A[ [:ascii:] ]{4,}\Z/x ) {
	return +(bless $this, ref($this).'::ASCII')->decode;
    }
    elsif ($data =~ /\A\x{04}.{64}+\Z/m) {
	return +(bless $this, ref($this).'::PublicKey')->decode;
    }
    else { return $this }
}
sub binary_data { my $_ = shift; decode_qp $_->{data} }

package Bitcoin::Script::PushData::ASCII;
our @ISA = qw(Bitcoin::Script::PushData);
sub decode {
    my $_ = shift;
    $_->{data} = $_->binary_data;
    return $_;
}

package Bitcoin::Script::PushData::PublicKey;
our @ISA = qw(Bitcoin::Script::PushData);
use Bitcoin::Address;
sub decode {
    my $_ = shift;
    $_->{address} = ''. new Bitcoin::Address
    unpack 'H*', Bitcoin::hash160 reverse $_->binary_data;
    return $_;
}

1;

__END__

=head1 TITLE

Bitcoin::Script

=head1 SYNOPSIS

    use Bitcoin::Script;

=head1 DESCRIPTION

This module implements the internal bitcoin scripting language.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
