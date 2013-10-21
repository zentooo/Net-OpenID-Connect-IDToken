package Net::OpenID::Connect::IDToken;
use 5.008005;
use strict;
use warnings;

our $VERSION = "0.01";

use parent qw/Exporter/;

use MIME::Base64 qw/encode_base64url/;
use Digest::SHA;
use JSON::WebToken qw//;

our @EXPORT = qw/encode_id_token decode_id_token/;


our $JWT_ENCODE = sub {
    my ($claims, $key, $alg, $extra_headers) = @_;
    JSON::WebToken->encode($claims, $key, $alg, $extra_headers);
};

our $JWT_DECODE = sub {
    my ($id_token, $key, $to_be_verified) = @_;
    JSON::WebToken->decode($id_token, $key, $to_be_verified);
};

sub encode_id_token {
    __PACKAGE__->encode(@_);
}

sub decode_id_token {
    __PACKAGE__->decode(@_);
}

sub encode {
    my ($class, $claims, $key, $alg, $opts, $extra_headers) = @_;
    my $id_token_claims = +{};

    if ( my $token = $opts->{token} ) {
        $id_token_claims->{a_hash} = $class->_generate_token_hash($token, $alg);
    }
    if ( my $code = $opts->{code} ) {
        $id_token_claims->{c_hash} = $class->_generate_token_hash($code, $alg);
    }

    return $JWT_ENCODE->(+{ %$claims, %$id_token_claims }, $key, $alg, $extra_headers);
}

sub _generate_token_hash {
    my ($class, $token, $alg) = @_;
    my $bits = substr($alg, 2); # 'HS256' -> '256'

    my $sha  = Digest::SHA->new($bits);
    unless ( $sha ) {
        # exception
    }
    $sha->add($token);

    return encode_base64url(substr($sha->digest, 0, $bits / 16));
}

sub decode {
    my ($class, $id_token, $key, $tokens) = @_;

    if ( $key ) {
        my $tokens_verify_code = sub {
            my ($header, $claims) = @_;

            if ( $tokens && $tokens->{token} ) {
                $class->_verify_a_hash($tokens->{token}, $header->{alg}, $claims->{a_hash});
            }
            if ( $tokens && $tokens->{code} ) {
                $class->_verify_c_hash($tokens->{code}, $header->{alg}, $claims->{c_hash});
            }

            return $key;
        };
        return $JWT_DECODE->($id_token, $tokens_verify_code, 1);
    }
    else {
        return $JWT_DECODE->($id_token, $key, 0);
    }
}

sub _verify_a_hash {
    my ($class, $access_token, $alg, $a_hash) = @_;
    unless ( $a_hash ) {
        #Net::OpenID::Connect::IDToken::Exception->throw(ERROR_IDTOKEN_A_HASH_NOT_FOUND);
    }
    unless ( $class->_verify_token_hash($access_token, $alg, $a_hash) ) {
        #Net::OpenID::Connect::IDToken::Exception->throw(ERROR_IDTOKEN_A_HASH_INVALID);
    }
}

sub _verify_c_hash {
    my ($class, $authorization_code, $alg, $c_hash) = @_;
    unless ( $c_hash ) {
        #Net::OpenID::Connect::IDToken::Exception->throw(ERROR_IDTOKEN_C_HASH_NOT_FOUND);
    }
    unless ( $class->_verify_token_hash($authorization_code, $alg, $c_hash) ) {
        #Net::OpenID::Connect::IDToken::Exception->throw(ERROR_IDTOKEN_C_HASH_INVALID);
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
    };
    my $key = ... # HMAC shared secret or RSA private key or ...


    my $id_token;

    # encode id_token
    $id_token = encode_id_token($claims, $key, "HS256");

    # encode id_token with a_hash and/or c_hash
    $id_token = encode_id_token($claims, $key, "HS256", +{
        token => "525180df1f951aada4e7109c9b0515eb",
        code  => "f9101d5dd626804e478da1110619ea35",
    });


    my $decoded_claims;

    # decode id_token without JWT verification
    $decoded_claims = decode_id_token($id_token);

    # decode id_token with JWT verification
    $decoded_claims = decode_id_token($id_token, $key);

    # decode id_token with JWT, a_hash and/or c_hash verification
    $decoded_claims = decode_id_token($id_token, $key, +{
        token => "525180df1f951aada4e7109c9b0515eb",
        code  => "f9101d5dd626804e478da1110619ea35",
    });

=head1 DESCRIPTION

Net::OpenID::Connect::IDToken is ...

=head1 LICENSE

Copyright (C) yokoe.naosuke.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

yokoe.naosuke E<lt>yokoe.naosuke@dena.jpE<gt>

=cut

