package Net::OpenID::Connect::IDToken;
use 5.008005;
use strict;
use warnings;

use MIME::Base64 qw/encode_base64url/;
use Digest::SHA;
use JSON::WebToken qw//;

our $VERSION = "0.01";

our $JWT_ENCODE = sub {
    my ($class, $claims, $key, $alg, $extra_headers) = @_;
    JSON::WebToken::encode($claims, $key, $alg, $extra_headers);
};

our $JWT_DECODE = sub {
    my ($class, $id_token, $key, $to_be_verified) = @_;
    JSON::WebToken::decode($id_token, $key, $to_be_verified);
};

sub encode_id_token {
    __PACKAGE__->encode(@_);
}

sub decode_id_token {
    __PACKAGE__->decode(@_);
}

sub encode {
    my ($class, $claims, $key, $alg, $extra_headers) = @_;
    my $id_token_claims;

    if ( my $token = delete $claims->{token} ) {
        $id_token_claims->{a_hash} = $class->_generate_token_hash($token, $alg);
    }
    if ( my $code = $claims->{code} ) {
        $id_token_claims->{c_hash} = $class->_generate_token_hash($code, $alg);
    }

    return $JWT_ENCODE->encode(+{ %$claims, %$id_token_claims }, $key, $alg, $extra_headers);
}

sub _generate_token_hash {
    my ($class, $token, $alg) = @_;
    my $bits = substr($alg, 2); # 'HS256' -> '256'
    my $sha  = Digest::SHA->new($bits);
    $sha->add($token);
    return encode_base64url(substr($sha->digest, 0, $bits / 16));
}

sub decode {
    my ($class, $id_token, $key, $to_be_verified, $token, $code) = @_;

    if ( $to_be_verified ) {
        my $tokens_verify_code = sub {
            my ($header, $claims) = @_;
            unless ( $class->_verify_token_hash($token, $header->{alg}, $claims->{a_hash} ) ) {
                Net::OpenID::Connect::IDToken::Exception->throw();
            }
            unless ( $class->_verify_token_hash($code, $header->{alg}, $claims->{c_hash} ) ) {
                Net::OpenID::Connect::IDToken::Exception->throw();
            }

            return $key;
        };
        return $JWT_DECODE->($id_token, $tokens_verify_code, $to_be_verified);
    }
    else {
        return $JWT_DECODE->($id_token, $key, $to_be_verified);
    }
}

sub _verify_token_hash {
    my ($class, $token, $alg, $token_hash) = @_;
    return $class->_generate_token_hash($token, $alg) eq $token_hash;
}

1;
__END__

=encoding utf-8

=head1 NAME

Net::OpenID::Connect::IDToken - It's new $module

=head1 SYNOPSIS

    use Net::OpenID::Connect::IDToken;

=head1 DESCRIPTION

Net::OpenID::Connect::IDToken is ...

=head1 LICENSE

Copyright (C) yokoe.naosuke.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

yokoe.naosuke E<lt>yokoe.naosuke@dena.jpE<gt>

=cut

