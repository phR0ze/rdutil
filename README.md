# rdutil
RustDesk utility to encrypt or decrypt RustDesk passwords.

This utility can be used to generate the permanent RustDesk password that can then be stored in
the `~/.config/rustdeskt/RustDeskt2.toml` configuration file for automated deployments.

### Disclaimer
This project comes with absolutely no guarantees or support of any kind. It is to be used at your own 
risk. Any damages, issues, losses or problems caused by the use of wmctl are strictly the 
responsiblity of the user and not the developer/creator of wmctl.

**WARNING** since the password encryption key that RustDesk uses is just your machine id this can 
easily be reversed by any user on your machine and offers zero protection. This also means that this 
value is not safe to be included in any public package or shared with anyone else. The only means of 
have any security at all is to make your configuration file only readable by your user and to never 
share it in any way shape or form and never include your password value in any packaging.

**WARNING** also note that as a result of this the password will also need to be generated for each 
machine separately during install time and can not be shared across machines as it is machine 
specific. Using a system like Nix will handle this properly as it will be generated dynamically at 
install time but other pre-packaged options are not a safe way to do this nor will the resulting 
package work on any machine except where it was created.

### Usage
```
Usage: ./rdutil [COMMAND] <password> [OPTIONS]
Options:
  --key <key>                 Alternate key to use for encryption
Commands:
  encrypt <plaintext>         Encrypt the given password
  decrypt <encrypted>         Decrypt the given password
```

Since RustDesk stores the password in `~/.config/rustdesk/RustDesk2.toml` as `password`. You can 
simply run `rdutil encrypt $PASSWORD` to then generate an encrypted value unique to your machine that 
can be used in the configuration file.

**Example**
```bash
$ rdutil encrypt foobar
```

**~/.config/rustdesk/RustDesk2.toml**
```toml
password = '00ZHkEf5C0rqwam5C0KgPAMKmINg8GgUE='
```

### Platform support
NixOS is the only tested platform, but this could easily be extended to support others

