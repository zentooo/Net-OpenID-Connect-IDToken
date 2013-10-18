# NAME

Net::OpenID::Connect::IDToken - It's new $module

# SYNOPSIS

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

# DESCRIPTION

Net::OpenID::Connect::IDToken is ...

# LICENSE

Copyright (C) yokoe.naosuke.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

yokoe.naosuke <yokoe.naosuke@dena.jp>
