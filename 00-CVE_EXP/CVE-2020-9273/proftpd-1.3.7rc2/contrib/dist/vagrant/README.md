# Example Vagrantfile for ProFTPD

For folks wanting to develop/test ProFTPD using Vagrant, here is an example
`Vagrantfile`, which installs the `proftpd-basic` package on an Ubuntu 14.04
box.  The installed server can be reached using:

    $ ftp vagrant@192.168.21.21

where the password is the same as the username.
