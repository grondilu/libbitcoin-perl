#!/usr/bin/perl
package Bitcoin::DataStream;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(CHAR UCHAR BYTE INT16 UINT16 INT32 UINT32 INT64 UINT64 STRING);
use strict;
use warnings;

# constants
#
use constant {
    CHAR	=> 'c',
    UCHAR	=> 'C',
    BYTE	=> 'C',
    INT16	=> 's',
    UINT16	=> 'S',
    INT32	=> 'l',
    UINT32	=> 'L',
    INT64	=> 'q',
    UINT64	=> 'Q',
    STRING	=> 'a*',
};

# predeclarations
#
sub new;
sub clear;
sub Read;
sub Write;
sub map_file;
sub seek_file;
sub close_file;
sub read_compact_size;
sub write_compact_size;
sub read_string;
sub write_string;
sub read_bytes;

# internal functions
sub Length;
sub calc_size;
sub _no_class;
sub _no_instance;

# definitions
#
sub new {
    my $class = shift->_no_instance;
    my $arg = shift;
    bless [
	0,		# reading cursor,
	''.$arg		# data string
    ], $class;
}

sub clear { my $_ = shift->_no_class; @$_[0,1] = (0, '') }

sub map_file {
    use File::Map;
    my $_ = shift->_no_class;
    my ($file, $start) = @_;
    $_->[0] = $start;
    File::Map::map_file $_->[1], $file;
}
sub seek_file { my $_ = shift->_no_class; $_->[0] = shift }
sub close_file { undef shift->_no_class->[1] }

sub Read {
    my $_ = shift->_no_class;
    my $what_to_read = shift;
    return $_->read_string if $what_to_read eq STRING;
    my $length = calc_size $what_to_read;
    my $result = unpack $what_to_read, substr $_->[1], $_->[0], $length;
    $_->[0] += $length;
    return $result;
}

sub Write {
    my $_ = shift->_no_class;
    my $what_to_write = shift;
    my $arg = shift;
    return $_->write_string($arg) if $what_to_write eq STRING;
    $_->[1] .= pack $what_to_write, $arg;
}

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
    $_->[1] .= $string;
}

sub read_bytes {
    my $_ = shift->_no_class;
    my $length = shift;
    die "buffer overflow" if $length > length($_->[1]) - $_->[0];
    my $result = substr $_->[1], $_->[0], $length;
    $_->[0] += $length;
    return $result;
}

sub read_compact_size {
    my $_ = shift->_no_class;
    my $size = ord substr $_->[1], $_->[0]++, 1;
    if    ($size == 253) { $size = $_->Read(CHAR) }
    elsif ($size == 254) { $size = $_->Read(UINT32) }
    elsif ($size == 255) { $size = $_->Read(UINT64) }
    return $size;
}

sub write_compact_size {
    my $_ = shift->_no_class;
    my $size = shift;
    if    ($size < 0)   { die "negative size" }
    elsif ($size < 253) { $_->[1] .= chr($size); }
    elsif ($size < 254) { $_->[1] .= "\xfd" . pack CHAR, shift }
    elsif ($size < 255) { $_->[1] .= "\xfe" . pack UINT32, shift }
    else                { $_->[1] .= "\xff" . pack UINT64, shift }
}

sub Length { scalar unpack 'a*', shift }
sub calc_size {
    my $_ = shift;
    /c/i ? 1 :
    /a$/i ? 1 :
    /s/i ? 2 :
    /l/i ? 4 :
    /q/i ? 8 :
    die "unknown format"
    ;
}

sub _no_class    { my $_ = shift; die "class method not implemented"    unless ref; return $_ }
sub _no_instance { my $_ = shift; die "instance method not implemented" if ref;     return $_ }

sub _read_num {
    my $_ = shift->_no_class;
    my $format = shift;
    my $length = calc_size $format;
    my $result = unpack $format, substr $_->[1], $_->[0], $length;
    $_->[0] += $length;
    return $result;
}

sub _write_num {
    my $_ = shift->_no_class;
    $_->[1] .= pack @_[0,1];
}

# unused functions (kept for historical)
sub _read_num;
sub _write_num;

sub read_boolean  { return substr(shift->read_bytes(1), 0, 1) ne chr 0 }
sub read_int16    { return shift->_read_num('s') }
sub read_uint16   { return shift->_read_num('S') }
sub read_int32    { return shift->_read_num('l') }
sub read_uint32   { return shift->_read_num('L') }
sub read_int64    { return shift->_read_num('q') }
sub read_uint64   { return shift->_read_num('Q') }

sub write_boolean { my $_ = shift; return $_->[1] .= chr(shift() ? 1 : 0 ) }
sub write_int16   { my $_ = shift; return $_->_write_num('s', shift) }
sub write_uint16  { my $_ = shift; return $_->_write_num('S', shift) }
sub write_int32   { my $_ = shift; return $_->_write_num('l', shift) }
sub write_uint32  { my $_ = shift; return $_->_write_num('L', shift) }
sub write_int64   { my $_ = shift; return $_->_write_num('q', shift) }
sub write_uint64  { my $_ = shift; return $_->_write_num('Q', shift) }


1;

__END__

=head1 TITLE

Bitcoin::DataStream

=head1 SYNOPSIS

    use Bitcoin::DataStream;

    $ds = new Bitcoin::DataStream;
    $ds->write_string("foo");

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
