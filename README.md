# cs-4910-project
This is a project for creating encrypted files that must be unlocked by multiple people.

## basic overview of the project
The point of this project is to have a shared password manager, where it requires more than one user to supply their key before a password can be unlocked. Kind of like how nuclear launch facilities require keys from 2 operators rather than just one.

The password should be stored by the server. Before the password is sent to the server it should be encrypted by each user.

Encryption should be commutitave, which means that the order in which the program is decrypted should not matter. A user should be allowed to partially decrypt the file and then exit, allowing other users to use their keys to decrypt the file further. It should probably be the case that the clients are fully in charge of decrypting the file (IE they download it from the server, decrypt their part, and re-upload).

Who actually gets the password file should be defined in a policy (see the github issues for more info)

This project is split into two parts, the client and the server. The server is a daemon that can store encrypted password files for later decryption by clients. The clients are the programs that encrypt the files, and get the final results. 


