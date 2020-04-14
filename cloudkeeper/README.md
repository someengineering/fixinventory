# cloudkeeper
Houskeeping for Clouds

## Development Setup
```
$ git clone https://github.com/mesosphere/cloudkeeper.git
$ cd cloudkeeper
$ python3.8 -m venv venv
$ source venv/bin/activate
$ pip install --upgrade --editable cloudkeeper/
$ find plugins/ -maxdepth 1 -mindepth 1 -type d -exec pip install --upgrade --editable "{}" \+
```

## Example usage
```
$ eval $(maws li production)
$ cloudkeeper --plugin aws --aws-region us-west-2
```
