from authwatch.exporters import render


def test_plain_format():
    out = render(["1.1.1.1", "2.2.2.2"], "plain")
    assert out.strip().splitlines() == ["1.1.1.1", "2.2.2.2"]


def test_iptables_format():
    out = render(["1.1.1.1"], "iptables")
    assert "iptables -A INPUT -s 1.1.1.1 -j DROP" in out


def test_ufw_format():
    out = render(["1.1.1.1"], "ufw")
    assert "ufw deny from 1.1.1.1" in out


def test_dedup_and_sort():
    out = render(["2.2.2.2", "1.1.1.1", "1.1.1.1"], "plain")
    assert out.strip().splitlines() == ["1.1.1.1", "2.2.2.2"]


def test_empty_input():
    assert render([], "plain") == ""
