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

# DESCRIPTION

Net::OpenID::Connect::IDToken is ...

# LICENSE

Copyright (C) yokoe.naosuke.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

yokoe.naosuke <yokoe.naosuke@dena.jp>
