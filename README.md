![hashCrack](https://user-images.githubusercontent.com/75953873/176808767-e76632dd-1118-4c80-a483-f361a9e07887.png)

## Características
- Soporta MD5, SHA1, SHA-224, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512.
- Guarda los hashes crackeados en un archivo de texto plano.

![Supportedhashes](https://user-images.githubusercontent.com/75953873/176814598-71f2025a-77b6-46c6-828b-3967d44e22b4.png)


## Insallation
```
> git clone https://github.com/R3LI4NT/hashCRACK

> cd hashCrack

> pip3 install -r requirements.txt
```

## Uso
| COMMAND | HASH |
| ------------- | ------------- |
| --md5 | MD5  |
| --sha1  | SHA-1  |
| --sha224  | SHA-224  |
| --sha256  | SHA-256  |
| --sha384  | SHA-384  |
| --sha512  | SHA-512  |
| --sha3-224  | SHA3-224  |
| --sha3-256  | SHA3-256  |
| --sha3-384  | SHA3-384  |
| --sha3-512  | SHA3-512  |

### Otros
| COMMAND | DESCRIPTION |
| ------------- | ------------- |
| -w / --wordlist | Wordlist for brute force attack |
| -o / --output | Output file (optional) |
| --hashes | List of supported hashes |
| -h / --help | Request help |

`EJEMPLO:` **MD5 hash Cracking**

```python
python3 hashcrack.py --md5 <hash> --wordlist <wordlist> --output <filename>
```
![example](https://user-images.githubusercontent.com/75953873/176811897-461b7e79-cbf4-45a0-a3bb-e608cf17cc82.png)

</br>

### Testeado en Termux

![termux](https://user-images.githubusercontent.com/75953873/182391371-8c6cbaa9-88d7-4a31-ba29-1a9e5a12fa16.jpg)
