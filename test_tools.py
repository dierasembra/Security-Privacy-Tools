from security_privacy_tools.cli import find_in_text, estimate_entropy
def test_find_in_text():
    s = 'here is an aws key AKIAABCDEFGHIJKLMNOP and email user@test.com'
    findings = find_in_text(s)
    assert any('AWS' in name for name,_,_ in findings)
    assert any('user@test.com' in snippet or 'user@test.com' in ''.join(snippet for _,_,snippet in findings) for name,_,snippet in findings) if findings else True

def test_entropy():
    e = estimate_entropy('S3cureP@ssw0rd!')
    assert e > 0
