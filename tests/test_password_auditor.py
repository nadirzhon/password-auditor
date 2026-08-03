import sys, hashlib
sys.path.insert(0, ".")
from auditor import hash_string, generate_mutations, analyze_password

def test_md5_hash():
    result = hash_string("password", "md5")
    assert result == "5f4dcc3b5aa765d61d8327deb882cf99"

def test_sha1_hash():
    result = hash_string("admin", "sha1")
    assert result == "d033e22ae348aeb5660fc2140aec35850c4da997"

def test_sha256_hash():
    result = hash_string("test", "sha256")
    assert result == hashlib.sha256(b"test").hexdigest()

def test_mutations_not_empty():
    muts = generate_mutations("company")
    assert len(muts) > 5
    assert "COMPANY" in muts
    assert "Company" in muts

def test_mutations_leet():
    muts = generate_mutations("password")
    assert "p4ssw0rd" in muts or any("0" in m for m in muts)

def test_analyze_strong_password():
    score = analyze_password("Tr0ub4dor&3!xyz")
    assert score >= 70

def test_analyze_weak_password():
    score = analyze_password("abc")
    assert score < 40

if __name__ == "__main__":
    test_md5_hash()
    test_sha1_hash()
    test_sha256_hash()
    test_mutations_not_empty()
    test_mutations_leet()
    test_analyze_strong_password()
    test_analyze_weak_password()
    print("All tests passed.")
