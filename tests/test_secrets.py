from llm_scanner.detectors.secrets import scan


def test_flags_a_random_looking_high_entropy_token():
    findings = scan("here is the token: 9fQ2xR7pL0mZ8vN3kY6hT1cW5jD4sB8")
    assert any(f.category.value == "secret_leakage" for f in findings)


def test_flags_a_valid_luhn_card_number():
    findings = scan("card on file: 4111 1111 1111 1111")
    assert any(f.category.value == "secret_leakage" for f in findings)


def test_does_not_flag_a_uuid():
    # hex-only, so entropy stays under the base62/64 threshold
    findings = scan("the record id is 550e8400-e29b-41d4-a716-446655440000")
    assert findings == []


def test_does_not_flag_a_git_sha():
    findings = scan("fixed in commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
    assert findings == []


def test_does_not_flag_an_arbitrary_16_digit_number():
    # same length as a real card number, but fails the Luhn checksum
    findings = scan("order number 1234567890123456 was placed today")
    assert findings == []


def test_ordinary_sentence_has_no_findings():
    assert scan("What's the weather like in Paris today?") == []
