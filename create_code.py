import itertools
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GET_ITEM = "a"
EVAL = "b"
ADD = "c"
TO_CHAR = "d"
ZERO = "e"
ONE = "f"
USER_PASSWORD = "g"
HASH_COMPARISON = "h"

PASSWORD = "Passw0rd!"
PASSWORD_HASH = "e66860546f18cdbbcd86b35e18b525bffc67f772c650cedfe3ff7a0026fa1dee"
PASSWORD_BYTES = bytes.fromhex(PASSWORD_HASH)
PASSWORD_INTS = struct.unpack("32B", PASSWORD_BYTES)

print(PASSWORD_INTS)

IMPORT_HASHLIB = "import hashlib"
IMPORT_STRUCT = "import struct"
SINGLE_PARAM_LAMBDA = "lambda x,*_:"
MULTI_PARAM_LAMBDA = "lambda x,y:"
LAMBDA_EXEC = "exec(x, globals())"
LAMBDA_XOR = "x[0]^x[1]"
LAMBDA_OR = "x[0]|x[1]"
LAMBDA_HASH = "hashlib.sha256(x.encode('utf-8')).digest()"
LAMBDA_UNPACK = "struct.unpack('32B',x)"
LAMBDA_TUPLE = "(x,y)"

SINGLE_PARAM_LAMBDAS = [
    LAMBDA_EXEC,
    LAMBDA_XOR,
    LAMBDA_OR,
    LAMBDA_HASH,
    LAMBDA_UNPACK,
]

MULTI_PARAM_LAMBDAS = [LAMBDA_TUPLE]

IMPORTS = [IMPORT_STRUCT, IMPORT_HASHLIB]


def eval_code(code_steps, password):
    env = {
        GET_ITEM: lambda x, y: x[y],
        EVAL: lambda x, _: eval(x),
        ADD: lambda x, y: x + y,
        TO_CHAR: lambda x, _: chr(x),
        ZERO: 0,
        ONE: 1,
        USER_PASSWORD: password,
        HASH_COMPARISON: 0,
    }

    for i, (lhs, fn, arg1, arg2) in enumerate(code_steps):
        print("-" * 20, i * 4, lhs, fn, arg1, arg2, env[arg1], env[arg2], env["h"])

        env[lhs] = env[fn](env[arg1], env[arg2])

    return env["h"]


def find_combination(closest: int, n: int) -> tuple[int]:
    to_use = [1, 2, 4, 8, 16, 32]

    for i in range(len(to_use), 0, -1):
        for combination in itertools.combinations(to_use, i):
            if sum(combination) + closest == n:
                return combination


def construct_code() -> list[str]:
    steps = []

    alphabet = list(
        "ijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯІѢѲѴ"
        "абвгдеёжзийклмнопрстуфхцчшщъыьэюяіѣѳѵ"
        "θαωσεδρφτγψηυικολπμνβξχζ"
        "ΘΑΩΣΕΔΡΦΤΓΨΗΥΙΚΟΛΠΜΝΒΞΧΖ"
        "ԱԲԳԴԵԷԶԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖ"
        "աբգդեէզըթժիլխծկհձղճմյնշոչպջռսվտրցւփքօֆ"
    )
    integers = {0: ZERO, 1: ONE}
    chars = {}
    strings = {}
    functions = {}
    hash_bytes = []
    print(f"{len(alphabet)=}")

    def add_step(lhs: str, fn: str, arg1: str, arg2: str) -> None:
        steps.append(lhs + fn + arg1 + arg2)

    def next_letter() -> str:
        lhs = alphabet[0]
        del alphabet[0]
        return lhs

    def new_int(a: int, b: int) -> str:
        lhs = next_letter()
        add_step(lhs, ADD, integers[a], integers[b])
        integers[a + b] = lhs
        return lhs

    def construct_int(n: int) -> str:
        if n in integers:
            return integers[n]  # already have it

        for a in sorted(integers.keys(), reverse=True):
            for b in sorted(integers.keys(), reverse=False):
                if a + b == n:
                    return new_int(a, b)

        return construct_up_to(n)

    def construct_up_to(n: int) -> str:
        if n in integers:
            return integers[n]  # already have it

        closest = -1
        for integer in integers.keys():
            if closest < integer < n:
                closest = integer

        combination = find_combination(closest, n)

        location = None
        for num in combination:
            location = construct_int(closest := closest + num)
        return location

    def add_char(char: str) -> str:
        if char in chars:
            return chars[char]

        destination = next_letter()
        place_char(destination, char)
        chars[char] = destination
        return destination

    def place_char(destination: str, char: str) -> None:
        ascii_code = ord(char)
        add_step(destination, TO_CHAR, construct_int(ascii_code), ZERO)

    def add_string(to_add: str) -> str:
        if to_add in strings:
            return strings[to_add]
        destination = next_letter()

        first, *rest = to_add
        place_char(destination, first)
        for char in rest:
            add_step(destination, ADD, destination, add_char(char))
        strings[to_add] = destination
        return destination

    def new_function(func: str, lambda_: str) -> str:
        to_eval = next_letter()
        destination = next_letter()
        lambda_loc = add_string(lambda_)
        func_loc = add_string(func)

        print(lambda_ + func)

        add_step(to_eval, ADD, lambda_loc, func_loc)
        strings[lambda_ + func] = to_eval
        add_step(destination, EVAL, to_eval, ZERO)

        return destination

    # set basic ints
    for i in range(2, 33):
        construct_int(i)
    construct_int(64)
    construct_int(128)
    construct_int(192)
    construct_int(224)

    # add password bytes
    for password_int in PASSWORD_INTS:
        hash_bytes.append((password_int, construct_up_to(password_int)))

    # add lambda functions
    for function in SINGLE_PARAM_LAMBDAS:
        functions[function] = new_function(function, SINGLE_PARAM_LAMBDA)
    for function in MULTI_PARAM_LAMBDAS:
        functions[function] = new_function(function, MULTI_PARAM_LAMBDA)

    # exec imports
    import_loc = next_letter()
    for import_ in IMPORTS:
        add_step(import_loc, functions[LAMBDA_EXEC], add_string(import_), ZERO)
    add_step(import_loc, ADD, ZERO, ZERO)

    # hash user password
    user_hash_location = next_letter()
    add_step(user_hash_location, functions[LAMBDA_HASH], USER_PASSWORD, ZERO)
    add_step(user_hash_location, functions[LAMBDA_UNPACK], user_hash_location, ZERO)

    # compare hashes
    user_hash_buffer = next_letter()
    comparison_buffer = next_letter()
    xor_buffer = next_letter()
    or_buffer = next_letter()
    add_step(user_hash_buffer, ADD, ZERO, ZERO)
    add_step(comparison_buffer, ADD, ZERO, ZERO)
    add_step(xor_buffer, ADD, ZERO, ZERO)
    add_step(or_buffer, ADD, ZERO, ZERO)

    # compare provided password hash with stored hash
    for i, (hash_byte, _) in enumerate(hash_bytes):
        add_step(user_hash_buffer, GET_ITEM, user_hash_location, integers[i])
        add_step(
            xor_buffer,
            functions[LAMBDA_TUPLE],
            user_hash_buffer,
            integers[hash_byte],
        )
        add_step(comparison_buffer, functions[LAMBDA_XOR], xor_buffer, ZERO)
        add_step(
            or_buffer,
            functions[LAMBDA_TUPLE],
            comparison_buffer,
            HASH_COMPARISON,
        )
        add_step(HASH_COMPARISON, functions[LAMBDA_OR], or_buffer, ZERO)

    # null out important bits
    add_step(user_hash_buffer, ADD, ZERO, ZERO)
    add_step(comparison_buffer, ADD, ZERO, ZERO)
    add_step(xor_buffer, ADD, ZERO, ZERO)
    add_step(or_buffer, ADD, ZERO, ZERO)
    for function in functions.values():
        add_step(function, ADD, ZERO, ZERO)
    # leave one in as a hint
    for string in list(strings.values())[1:]:
        add_step(string, ADD, ZERO, ZERO)
    add_step(user_hash_location, ADD, ZERO, ZERO)

    print(f"{len(alphabet)=}")

    return steps


def main():
    code = construct_code()
    print(code)

    result = eval_code(code, PASSWORD)
    print(f"{result=}")

    with open("code.txt", mode="w", encoding="utf-8") as f:
        f.write("".join(code))

    backend = default_backend()
    key = PASSWORD_BYTES
    iv = b">\x1e\x8e\x8b\xd8\x9e\xfb\xd3:\x80\xfbb\x9e\xba\xfa\x1e"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"https://youtu.be/dQw4w9WgXcQ    ") + encryptor.finalize()
    print(iv)
    print(ct)


if __name__ == "__main__":
    main()
