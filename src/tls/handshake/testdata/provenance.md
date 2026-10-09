# TLS trace vectors

The four byte strings are from RFC 8448 §3, January 2019, Martin Thomson:
https://www.rfc-editor.org/rfc/rfc8448.txt. They are public test inputs, never
production credentials. The certificate uses an intentionally unacceptable
1024-bit RSA key; these vectors check transcript, key schedule and record
protection, not cloak certificate acceptance or live peer interoperability.

Copyright (c) 2019 IETF Trust and the persons identified as authors of the
code. All rights reserved. Redistribution and use in source and binary forms,
with or without modification, are permitted provided that source retains this
notice, conditions and disclaimer, and binary redistribution reproduces them
in accompanying materials. Neither the IETF Trust nor contributors' names may
be used to endorse derived products without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE, ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY OR CONSEQUENTIAL DAMAGES, HOWEVER CAUSED, ARISING FROM ITS USE.
