Better Password Practices for MyBB
==========================

**Built on the foundation laid by [tommm/password-hash](https://github.com/tommm/password-hash) by Tom Moore**

This MyBB plugin changes the cryptography method from salted password hashing to bcrypt (via PHP's `password_hash`) and disables the utterly moronic method of sending a user's first password via email.

## Requirements

- PHP 5.5 or later (for the `password_hash` function)
    + If your host doesn't support this, then I would consider finding a new host who keeps their systems moderately updated.



Please don't install this plugin until you have considered the caveats below.


Caveats
-----------
* The process is destructive; if you wish to deactivate/uninstall the plugin in the future, all users (including administrators) with converted passwords will need to request a new password through the Forgotten Password feature.
* The plugin uses PluginLibrary to perform a two edits to core files; you will need PluginLibrary 12 and for the files to be writeable to continue installation.
* Whenever you upgrade MyBB 1.8, you will need to perform the same edit to inc/functions_user.php to ensure you can login to complete the process.

Usage
-----------
Upload all files and install/activate the plugin via the ACP.

By default, the plugin will convert user passwords to bcrypt the next time users login or change their password. If you would rather users choose a new password, edit ./inc/plugins/psswrd_hsh.php and set `PSSWD_CONV` to `false`.
