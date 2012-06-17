#!/usr/bin/perl
package Bitcoin::Script;
use v5.14;
use strict;
use warnings;

use overload
'<<'	=> sub { bless [ @{$_[0]}, @{$_[1]} ] },
'&{}'	=> sub { my $this = shift; sub { $_->(@_) for @$this } },
;

sub new {
    my $class = shift; die 'instance method call not implemented' if ref $class;
    my $arg = shift;
    if    (not defined $arg or $arg eq '') { bless [], $class }
    elsif (ref $arg)                       {...}
    else {
	my $first_atom = do {
	    given(ord substr $arg, 0, 1) {
		when([1 .. 78])      { ($class.'::PushData')->new($arg) }
		when([0, 79 .. 255]) { ($class.'::OP')->new(substr $arg, 0, 1) }
		default { die 'unexpected value' }
	    }
	};
	bless [ $first_atom, @{$class->new(substr $arg, $first_atom->_length)} ], $class;
    }
}
sub code {
    my $this = shift;  die 'class method call not implemented' unless ref $this;
    join '', map $_->code, @$this;
}

sub unbless { [ map $_->unbless, @{shift()} ] }

package Bitcoin::Script::Atom;
our @ISA = qw(Bitcoin::Script);
use Bitcoin::Script::Codes;
use overload
q(@{})	=> sub { [ shift ] },
q(&{})	=> sub { my $op_code = shift->{op_code}; ${$Bitcoin::Script::Codes::{$op_code}}->[1] },
;

sub new {
    my $class = shift; die 'instance method call not implemented' if ref $class;
    my $arg   = shift;
    my $first_char_ord = ord substr $arg, 0, 1;
    bless {
	'op_code' => $Bitcoin::Script::Codes::Inverse_code{$first_char_ord} // 'N/A',
    }, $class;
}
sub code { my $_ = shift; $_->{code} // sprintf '%2x', ${'Bitcoin::Script::Codes::'.$_->{op_code}}->[0] }
sub _length { my $_ = shift; length($_->code) / 2 }
sub unbless { +{ %{shift()} } }

package Bitcoin::Script::OP;
our @ISA = qw(Bitcoin::Script::Atom);
use overload q(@{}) => sub { [ shift ] };
sub new {
    my $class = shift; die 'instance method call not implemented' if ref $class;
    my $arg   = shift;
    my $this = $class->SUPER::new($arg);
    $this->{code} = unpack 'H2', substr $arg, 0, 1;
    return $this;
}

package Bitcoin::Script::PushData;
our @ISA = qw(Bitcoin::Script::Atom);
use overload
q(&{})	=> sub { my $this = shift; sub { use Bitcoin::Script::Stack qw(Push); Push $this->data } },
;

sub data { my $this = shift; substr pack('H*', $this->{code}), $this->{offset} }
sub new {
    my $class = shift; die 'instance method call not implemented' if ref $class;
    my $arg = shift;
    my $this = $class->SUPER::new($arg);
    my ($offset, $length) = do {
	given (ord substr $arg, 0, 1) {
	    when([0 .. 75]) { 1, $_ }
	    when(      76 ) { 2, ord          substr $arg, 1, 1 }
	    when(      77 ) { 3, unpack 'S>', substr $arg, 1, 2 }
	    when(      78 ) { 5, unpack 'L>', substr $arg, 1, 4 }
	    default  { die 'unexpected value' }
	}
    };
    $this->{code} = unpack 'H*', substr $arg, 0, $offset + $length;
    for (substr $arg, $offset, $length) {
	if (/\A[ [:ascii:] ]{4,}\Z/x ) {
	    $this->{text} = $_;
	    return bless $this, $class.'::ASCII';
	}
	elsif (/\A\x{04}(?<x>.{32})(?<y>.{32})\Z/ms)    {
	    use bigint;
	    require Bitcoin;
	    $this->{address} = Bitcoin::Address->new(
		bless { map { $_ => hex unpack 'H*', $+{$_} } qw(x y) }, 'EC::DSA::PublicKey'
	    );
	    return bless $this, $class.'::PublicKey';
	}
	else {
	    $this->{offset} = $offset;
	    return $this;
	}
    }
}

package Bitcoin::Script::PushData::ASCII;
our @ISA = qw(Bitcoin::Script::PushData);
sub data { shift->{text} }

package Bitcoin::Script::PushData::PublicKey;
our @ISA = qw(Bitcoin::Script::PushData);
sub data { substr pack('H*', shift->{code}), 1 }

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
