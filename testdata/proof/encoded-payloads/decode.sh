#!/bin/bash
echo dGhpcyBpcyBhIGZha2UgcGF5bG9hZA== | base64 --decode | bash
printf '\x48\x65\x6c\x6c\x6f\x57\x6f\x72\x6c\x64' > /tmp/.hidden
base64 -d <<< "c3RhZ2UyLnNo" | base64 -d | bash
certutil -decode encoded.txt decoded.exe
