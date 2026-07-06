This is A Project I have been working on for a while to provide a secure way to encrypt and decrypt through stacking encryption techniques with obfuscation techniques and implementing integrity checks. When you download it, please delete "DELETEME" in PGPKeys, it was a placeholder so git let me upload the essential folder

**How do I use it?**

Please read `INSTRUCTIONS.txt` which contains project information, setup instructions and then usage instructions including how to share messages with friends. If you have any issues or errors, please check `Troubleshooting.txt` which contains common issues people might be having and the solutions to them and also contains contact informatin to contact me if your issue isnt listed

**What does it Actually do?**

This Project takes any message or piece of text, encrypts it with AES-256 in GCM mode (which is the hardest to crack), adds a few informational parts onto it like a hash and password number, encrypts it with PGP then uses invisible unicode characters that dont visually appear (as in theyre there but dont take up any space) to make an invisible message that you can send it to your friend who uses a shared password list and their PGP Keypair to verify the message wasnt changed and decrypt the message. This project also implements a mandatory policy which makes your password lists to stay locked while you use it so if someone found the password files they're encrypted alredy and are only decrypted when you need to use them. My project also deletes used passwords from the list and attaches data telling the person you sent it to which password to automatically delete so no one can look up that password number (index). it also uses multiple (and changable) invisible unicode characters so someone cant just decode the message into binary to start cracking it.

> When downloading the release, please check the SHA256 hash of the release matches the hash on: https://www.geocities.ws/coffeecity/checksum.txt

This work is licensed under a
[Creative Commons Attribution-NonCommercial-NoDerivs 4.0 International License][cc-by-nc-nd].

[![DOI][doi-badge]][doi-link] [![CC BY-NC-ND 4.0][cc-by-nc-nd-shield]][cc-by-nc-nd] [![CC BY-NC-ND 4.0][cc-by-nc-nd-image]][cc-by-nc-nd]

[doi-badge]: https://zenodo.org/badge/1263553676.svg
[doi-link]: https://doi.org/10.5281/zenodo.20618724
[cc-by-nc-nd]: http://creativecommons.org/licenses/by-nc-nd/4.0/
[cc-by-nc-nd-image]: https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png
[cc-by-nc-nd-shield]: https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey.svg

**Archives of this repository can be found at the following sites:**
> - https://zenodo.org/records/20721745
> - perma.cc - https://perma.cc/66H7-6GPB
> - archive.today/archive.ph - https://archive.ph/NP3eY
> - ghostarchive.org - https://ghostarchive.org/archive/DI9G7
> - thewaybackmachine - https://web.archive.org/web/20260615025237/https://github.com/starcrestmc/Encryptor-v6
