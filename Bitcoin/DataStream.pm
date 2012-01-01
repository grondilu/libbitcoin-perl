#!/usr/bin/perl
package Bitcoin::DataStream;
use strict;
use warnings;

# predeclarations
#
sub new;
sub clear;
sub Write;
sub read_compact_size;
sub write_compact_size;
sub read_string;
sub read_bytes;

# internal functions
sub _read_num;
sub Length;
sub calc_size;
sub _no_class;
sub _no_instance;

# definitions
#
sub new {
    my $class = shift->_no_instance;
    my $arg = shift;
    bless [ ref $arg ?  @$arg : 
	(0,		# cursor for reading,
	''.$arg)	# data string
    ], $class;
}

sub clear { my $_ = shift->_no_class; @$_[0,1] = (0, ''); return $_ }
sub Write { my $_ = shift->_no_class; $_->[1] .= shift }

sub read_string {
    my $_ = shift->_no_class;
    die "data stream is empty" if $_->[1] eq '';
    my $length = $_->read_compact_size;
    $_->read_bytes($length);
}

sub write_string {
    my $_ = shift->_no_class;
    my $string = shift;
    $_->write_compact_size(Length $string);
    $_->Write($string);
}

sub read_bytes {
    my $_ = shift->_no_class;
    my $length = shift;
    die "buffer overflow" if $length > length($_->[1]) - $_->[0];
    my $result = substr @$_[1,0], $length;
    $_->[0] += $length;
    return $result;
}

sub read_boolean  { return substr(shift->read_bytes(1), 0, 1) ne chr 0 }
sub read_int16    { return shift->_read_num('s') }
sub read_uint16   { return shift->_read_num('S') }
sub read_int32    { return shift->_read_num('l') }
sub read_uint32   { return shift->_read_num('L') }
sub read_int64    { return shift->_read_num('q') }
sub read_uint64   { return shift->_read_num('Q') }

sub write_boolean { my $_ = shift; return $_->Write(chr(shift() ? 1 : 0 )) }
sub write_int16   { my $_ = shift; return $_->_write_num('s', shift) }
sub write_uint16  { my $_ = shift; return $_->_write_num('S', shift) }
sub write_int32   { my $_ = shift; return $_->_write_num('l', shift) }
sub write_uint32  { my $_ = shift; return $_->_write_num('L', shift) }
sub write_int64   { my $_ = shift; return $_->_write_num('q', shift) }
sub write_uint64  { my $_ = shift; return $_->_write_num('Q', shift) }

sub read_compact_size {
    my $_ = shift->_no_class;
    my $size = ord substr $_->[1], $_->[0]++, 1;
    if    ($size == 253) { $size = $_->_read_num('C') }
    elsif ($size == 254) { $size = $_->_read_num('L') }
    elsif ($size == 255) { $size = $_->_read_num('Q') }
    return $size;
}

sub write_compact_size {
    my $_ = shift->_no_class;
    my $size = shift;
    if    ($size < 0)   { die "negative size" }
    elsif ($size < 253) { $_->Write($size); }
    elsif ($size < 254) { $_->Write("\xfd"); $_->_write_num('C', shift) }
    elsif ($size < 255) { $_->Write("\xfe"); $_->_write_num('L', shift) }
    else                { $_->Write("\xff"); $_->_write_num('Q', shift) }
}

sub _read_num {
    my $_ = shift->_no_class;
    my $format = shift;
    my $length = calc_size $format;
    my $result = unpack $format, substr @$_[1,0], $length;
    $_->[0] += $length;
    return $result;
}

sub _write_num {
    my $_ = shift->_no_class;
    $_->Write(unpack @_[0,1]);
}

sub Length { scalar unpack 'a*', shift }
sub calc_size {
    my $_ = shift;
    /c/i ? 1 :
    /s/i ? 2 :
    /l/i ? 4 :
    /q/i ? 8 :
    die "unknown format"
    ;
}

sub _no_class    { my $_ = shift; die "class method not implemented"    unless ref; return $_ }
sub _no_instance { my $_ = shift; die "instance method not implemented" if ref;     return $_ }


1;

__END__

=head1 TITLE

Bitcoin::DataStream

=head1 SYNOPSIS

    use Bitcoin::DataStream;

=head1 DESCRIPTION

This implements bitcoin's data stream format.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 CREDITS

This is a straightforward translation of Gavin Andersen's I<bitcointools>.
See https://github.com/gavinandresen/bitcointools

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
