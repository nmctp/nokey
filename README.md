# no more clear text passwords

## What?

*no more clear text passwords* is a project to stop the nonsense regarding passwords used in the login protocols of most Web 2.0 projects: they are sent in the clear, shamelessly, with absolutely no care for privacy, and without warning the users.

Of course, those projects (some of them) allow the users to opt for a fully-secured connection, but you know, if you are just updating a blog, you simply don’t care about your connection being encrypted (as far as we know, a blog’s contents are usually written to be pubic, ditto for the wikipedia). Also, asking the wikipedia servers to encrypt all the traffic seems a bit overkill.

We also aim at POP3, IMAP and SMTP servers which do not necessarily need the full power of SSL or TLS, but which, please, should never allow their users to simply shout their passwords.

Actually, we think a simple tweak of a lot of logging protocols would make the Internet much safer without overloading the servers all the time (just while logging the users in). Think even telnet and (do we dare say it?) ftp!

## Why?

Because we think transmitting passwords in the clear is tantamount to shouting them on your backyard. And because we are pretty much sure that a lot of people (we are thinking both elderly people and youngsters) use the same password for their bank-account transfers and their personal blog.

And, no, we do not think they are dumb, we think they are just misinformed.

## Who?

We are two friends; Pedro Fortuny Ayuso is a Mathematician with a great bias towards IT and Rafael Casado Sanchez is a Computer Scientist.

## How?

Due to the PHP-orientation of most CMS’s and wikis out there, we have decided to implement a C version of the software together with an easy-to-port PHP version. The latter will be, for obvious reasons, much slower than the former, but also probably easy to install on unfriendly or difficult to manage hosts.

We use either RSA or Shamir’s no-key protocol (aka “Three-pass protocol”) to encrypt the password. No more than that.

Notice that this project seeks secrecy for passwords, but is not aimed at fighting man-in-the-middle attacks. There is a difference between not shouting your password and fighting an active criminal.
