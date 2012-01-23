#!/usr/bin/perl
package Bitcoin::DataStream;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(CHAR UCHAR BYTE INT16 UINT16 INT32 UINT32 INT64 UINT64 STRING);
%EXPORT_TAGS = ( types => [ @EXPORT_OK ] );
use v5.14;
use strict;
use warnings;

# data types
use constant {
    BYTE	=> 'a',
    CHAR	=> 'c',
    UCHAR	=> 'C',
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
sub depth;
sub Read;
sub Write;
sub map_file;
sub seek_file;
sub close_file;
sub read_compact_size;
sub write_compact_size;
sub write_string;
sub read_bytes;

# internal functions
sub calc_size;
sub _no_class;
sub _no_instance;

# definitions
#
sub new {
    my $class = shift->_no_instance;
    my $arg = shift // '';
    bless {
	cursor => 0,		# reading cursor,
	input  => $arg      	# data string
    }, $class;
}

# ro accessors
sub cursor { shift->_no_class->{cursor} }
sub input  { shift->_no_class->{input} }

# overloading
use overload
'""' => sub { unpack 'H*', shift->input },
;

# methods
#
sub clear { my $_ = shift->_no_class; @$_[0,1] = (0, '') }
sub depth { length shift->{input} }

sub map_file {
    use File::Map;
    my $_ = shift->_no_class;
    my ($file, $start) = @_;
    $_->{cursor} = $start;
    File::Map::map_file $_->{input}, $file;
    return $_;
}
sub seek_file  { my $_ = shift->_no_class; $_->{cursor} = shift }
sub close_file { undef shift->_no_class->{input} }

sub Read {
    my $_ = shift->_no_class;
    die "data stream is empty" unless my $depth = $_->depth;
    my $what_to_read = shift;
    my $length = $_->calc_size($what_to_read);
    die "index out of buffer" if $length > $depth - $_->{cursor};
    my $result = unpack $what_to_read, substr $_->{input}, $_->{cursor}, $length;
    $_->{cursor} += $length;
    return $result;
}

sub Write {
    my $_ = shift->_no_class;
    my $what_to_write = shift;
    die 'argument expected' unless defined $what_to_write;
    my $arg = shift;
    if ($what_to_write eq STRING) { $_->write_string($arg) }
    else { $_->{input} .= defined $arg ? pack $what_to_write, $arg : $what_to_write }
}

sub write_string {
    my $_ = shift->_no_class;
    my $string = shift;
    $_->write_compact_size(length $string);
    $_->{input} .= $string;
}

sub read_bytes {
    my $_ = shift->_no_class;
    my $length = shift;
    die "buffer overflow" if $length > length($_->{input}) - $_->{cursor};
    my $result = substr $_->{input}, $_->{cursor}, $length;
    $_->{cursor} += $length;
    return $result;
}

sub read_compact_size {
    my $_ = shift->_no_class;
    my $size = ord substr $_->{input}, $_->{cursor}++, 1;
    if    ($size == 253) { $size = $_->Read(UINT16) }
    elsif ($size == 254) { $size = $_->Read(UINT32) }
    elsif ($size == 255) { $size = $_->Read(UINT64) }
    return $size;
}

sub write_compact_size {
    my $_ = shift->_no_class;
    my $size = shift;
    if    ($size < 0)   { die "negative size" }
    elsif ($size < 253) { $_->{input} .= chr($size); }
    elsif ($size < 254) { $_->{input} .= "\xfd" . pack UINT16, shift }
    elsif ($size < 255) { $_->{input} .= "\xfe" . pack UINT32, shift }
    else                { $_->{input} .= "\xff" . pack UINT64, shift }
}

sub calc_size {
    my $this = shift;
    given( shift ) {
	when( [ CHAR, BYTE ] )      { return 1 }
	when( [ INT16, UINT16 ] )   { return 2 }
	when( [ INT32, UINT32 ] )   { return 4 }
	when( [ INT64, UINT64 ] )   { return 8 }
	when( /@{[BYTE]}(\d+)\Z/i ) { return $1 }
	when( STRING )              { return $this->read_compact_size }
	default                     { die 'unknown format' }
    }
}

sub _no_class    { my $_ = shift; die "class method not implemented"    unless ref; return $_ }
sub _no_instance { my $_ = shift; die "instance method not implemented" if ref;     return $_ }

1;

__END__

=begin comment

# unused functions (kept here for historical)
sub _read_num {
    my $_ = shift->_no_class;
    my $format = shift;
    my $length = calc_size $format;
    my $result = unpack $format, substr $_->{input}, $_->{cursor}, $length;
    $_->{cursor} += $length;
    return $result;
}

sub _write_num {
    my $_ = shift->_no_class;
    $_->{input} .= pack @_[0,1];
}

sub read_string {
    my $_ = shift->_no_class;
    die "data stream is empty" if $_->{input} eq '';
    my $length = $_->read_compact_size;
    $_->read_bytes($length);
}

sub read_boolean  { return substr(shift->read_bytes(1), 0, 1) ne chr 0 }
sub read_int16    { return shift->_read_num('s') }
sub read_uint16   { return shift->_read_num('S') }
sub read_int32    { return shift->_read_num('l') }
sub read_uint32   { return shift->_read_num('L') }
sub read_int64    { return shift->_read_num('q') }
sub read_uint64   { return shift->_read_num('Q') }

sub write_boolean { my $_ = shift; return $_->{input} .= chr(shift() ? 1 : 0 ) }
sub write_int16   { my $_ = shift; return $_->_write_num('s', shift) }
sub write_uint16  { my $_ = shift; return $_->_write_num('S', shift) }
sub write_int32   { my $_ = shift; return $_->_write_num('l', shift) }
sub write_uint32  { my $_ = shift; return $_->_write_num('L', shift) }
sub write_int64   { my $_ = shift; return $_->_write_num('q', shift) }
sub write_uint64  { my $_ = shift; return $_->_write_num('Q', shift) }

=end comment

=head1 TITLE

Bitcoin::DataStream

=head1 SYNOPSIS

    use Bitcoin::DataStream qw( :types );

    $ds = new Bitcoin::DataStream;
    $ds->Write(STRING, "foo");
    $ds->Write(UINT32, 2**24 + 3**5);
    $ds->Write(STRING, "foo");

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
