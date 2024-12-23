# ngx_http_access_control_module

# Name

A custom Nginx module for advanced access control based on variables.

# Table of Content

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Installation](#installation)
* [Directives](#directives)
  * [access](#access)
  * [access_deny_status](#access_deny_status)
* [Author](#author)
* [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
server {
    listen 80;
    server_name example.com;

    # Allow access if $var2 is non-empty and not zero. The allowed request will no longer match the remaining access control rules.
    access allow $var1;

    # Deny access if $var1 is non-empty and not zero
    access deny $var2;

    location / {
        # Your other configurations
    }

    location /restricted {
        # Override deny status code
        access_deny_status 404;

        # Deny access if $var3 is non-empty and not zero
        access deny $var3;
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_access_control_module`.

# Directives

## access

**Syntax:** *access [allow|deny] variable;*

**Default:** *-*

**Context:** *http, server, location*

The access directive defines an access control rule based on a variable. The variable is evaluated at runtime, and if it is non-empty and not zero, the rule is considered matched.

allow: Allows access if the condition is met. The allowed request will no longer match the remaining access control rules.
deny: Denies access if the condition is met.


## access_rules_inherit

**Syntax:** *access_rules_inherit off | before | after;*

**Default:** *access_rules_inherit off;*

**Context:** *http, server, location*

determines whether and how access control rules from previous level are applied in the current configuration context. It accepts three values:

off: do not inherit any access rules from previous level, unless no access directive is defined at the current level.
before: apply access rules of previous level before the access rules of current level.
after: apply access rules of previous level after the access rules of current level.

## access_deny_status

**Syntax:** *access_deny_status code;*

**Default:** *access_deny_status 403;*

**Context:** *http, server, location*

Sets the HTTP status code to return in response when access is denied by a deny rule.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
