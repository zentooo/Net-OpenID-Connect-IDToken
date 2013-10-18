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
    $to_be_verified = 1 if ! defined $to_be_verified;

    if ( $to_be_verified ) {
        my $tokens_verify_code = sub {
            my ($header, $claims) = @_;
            if ( $token && $claims->{a_hash} && ! $class->_verify_token_hash($token, $header->{alg}, $claims->{a_hash} ) ) {
                Net::OpenID::Connect::IDToken::Exception->throw();
            }
            if ( $code && $claims->{c_hash} && ! $class->_verify_token_hash($code, $header->{alg}, $claims->{c_hash} ) ) {
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

    use Net::OpenID::Connect::IDToken qw/encode_id_token decode_id_token/;

    my $claims = +{
        jti   => 1,
        sub   => "http://example.owner.com/user/1",
        aud   => "http://example.client.com",
        iat   => 1234567890,
        exp   => 1234567890,
        token => "525180df1f951aada4e7109c9b0515eb",
        code  => "f9101d5dd626804e478da1110619ea35",
    };
    my $key1 = ... # HMAC shared secret or RSA private key or ...

    my $id_token = encode_id_token($claims, $key1, "HS256");

    my $key2 = ... # HMAC shared secret or RSA public key or ...

    my $decoded_claims;
    $decoded_claims = decode_id_token($id_token, $key2, 0);                # decode without JWT verification and a_hash/c_hash verification
    $decoded_claims = decode_id_token($id_token, $key2);                   # decode with JWT verification, without a_hash/c_hash verification
    $decoded_claims = decode_id_token($id_token, $key2, 1, $token, $code); # decode with JWT verification and a_hash/c_hash verification
    $decoded_claims = decode_id_token($id_token, $key2, 1, $token);        # decode with JWT verification and a_hash verification
    $decoded_claims = decode_id_token($id_token, $key2, 1, undef, $code);  # decode with JWT verification and c_hash verification

=head1 DESCRIPTION

Net::OpenID::Connect::IDToken is ...

=head1 LICENSE

Copyright (C) yokoe.naosuke.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

yokoe.naosuke E<lt>yokoe.naosuke@dena.jpE<gt>

=cut

