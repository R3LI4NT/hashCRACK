![hashCrack](https://user-images.githubusercontent.com/75953873/176808767-e76632dd-1118-4c80-a483-f361a9e07887.png)

## Features
- Supports MD5, SHA1, SHA256, SHA-224, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512
- Can save the hashes to a file

## Insallation
```
> git clone https://github.com/R3LI4NT/hashCrack

> cd hashCrack

> pip3 install -r requirements.txt
```

## Usage
| HASH | COMMAND |
| ------------- | ------------- |
| MD5 | --md5  |
| SHA-1  | --sha1  |
| SHA-224  | --sha224  |
| SHA-256  | --sha256  |
| SHA-384  | --sha384  |
| SHA-512  | --sha512  |
| SHA3-224  | --sha3-224  |
| SHA3-256  | --sha3-256  |
| SHA3-384  | --sha3-384  |
| SHA3-512  | --sha3-512  |

### Input and Output
| DESCRIPTION | COMMAND |
| ------------- | ------------- |
| Wordlist for brute force attack | -w / --wordlist |
| Output file (optional) | -o / --output |
| Request help | -h / --help |

`EXAMPLE:` **MD5 hash Cracking**

```python
python3 hashcrack.py --md5 <hash> --wordlist <wordlist> --output <filename>
```
![example](https://user-images.githubusercontent.com/75953873/176811897-461b7e79-cbf4-45a0-a3bb-e608cf17cc82.png)
