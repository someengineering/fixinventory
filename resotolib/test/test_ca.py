import pickle
from resotolib.core.ca import TLSData


def test_tls_data():
    t1 = TLSData("test123")
    t2 = pickle.loads(pickle.dumps(t1))
    assert t1.common_name == t2.common_name
