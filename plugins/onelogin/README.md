# resoto-plugin-onelogin
OneLogin collector plugin for Cloudkeeper

This plugin collects OneLogin users as cloud resources and adds them to the Cloudkeeper graph for use by other plugins.

## Usage
Retrieve OneLogin API credentials and provide them to the plugin either as environment variables or commandline arguments.

### Example
```
$ resoto --collector onelogin \
    --onelogin-region us \
    --onelogin-client-id f63e68ac0bf052ae923c03f5b12aedc6cca49874c1c9b0ccf3f39b662d1f487b \
    --onelogin-client-secret 95fdbdf2fea4b306d059facf26c18d94cb190189a3221008eca14c5dd0b0fce1

OR

$ export ONELOGIN_CLIENT_REGION=us
$ export ONELOGIN_CLIENT_ID=f63e68ac0bf052ae923c03f5b12aedc6cca49874c1c9b0ccf3f39b662d1f487b
$ export ONELOGIN_CLIENT_SECRET=95fdbdf2fea4b306d059facf26c18d94cb190189a3221008eca14c5dd0b0fce1
$ resoto --collector onelogin
```

## List of arguments
```
  --onelogin-region ONELOGIN_REGION
                        OneLogin Region
  --onelogin-client-id ONELOGIN_CLIENT_ID
                        OneLogin Client ID
  --onelogin-client-secret ONELOGIN_CLIENT_SECRET
                        OneLogin Client Secret
```
