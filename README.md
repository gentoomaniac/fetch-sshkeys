# fetch-sshkeys

## sshd configuration
Set the authorized_keys path to something users don't have access to.
Use the same base path for fetch-sshkeys
```
AuthorizedKeysFile      /etc/userkeys/%u/authorized_keys
```

## How to run
```shell
./main.py -v update-keys -m -d
```