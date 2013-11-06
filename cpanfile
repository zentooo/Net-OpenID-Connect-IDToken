requires 'perl', '5.008001';

requires 'JSON::WebToken', '0.07';

on 'test' => sub {
    requires 'Test::More', '0.98';
    requires 'Test::Exception', '0.32';
};
