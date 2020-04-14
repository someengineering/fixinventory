from cloudkeeper.baseresources import BaseResource


class SomeTestResource(BaseResource):
    resource_type = 'some_test_resource'


def test_resource():
    r = SomeTestResource('foo', {'foo': 'bar'})
    log_msg = 'some log'
    r.log(log_msg)
    assert r.id == 'foo'
    assert r.name == 'foo'
    assert r.resource_type == 'some_test_resource'
    assert r.tags['foo'] == 'bar'
    assert r.event_log[0]['msg'] == log_msg
