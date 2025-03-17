# YARA Rule Generator

## 📖 About
YARA Rule Generator is a Python-based tool designed to simplify the creation of YARA rules for malware analysis and threat detection. It allows users to define custom string-based detection rules, apply conditions (`any` or `all`), and search for encoded strings (such as base64 and hexadecimal). The generated rules can be used for scanning directories recursively, helping security professionals automate and enhance their detection workflows.

## 🚀 Features

- Automatic YARA rule generation.
- Supports `any` or `all` conditions.
- Option to search for strings in base64 or hexadecimal.
- Saves the generated rule in a `.yar` file.

## 📌 Prerequisites

- Python 3.x installed.

## 📥 Installation

Clone this repository or download the script manually:

```sh
git clone https://github.com/ailsongabriel/YaraRuleGenerator.git
cd YaraRuleGenerator
```

## ⚙️ Usage

Run the script with the following arguments:

```sh
python yara_generator.py -o <output_file>.yar -c <condition> -s <string1> <string2> ... [-b <base64_indexes>] [-x <hex_indexes>]
```

### 🔹 Arguments

| Parameter         | Description                                                                         |
| ----------------- | ---------------------------------------------------------------------------------- |
| `-o, --output`    | Output file name. Default: `StringSearch.yar`.                                     |
| `-c, --condition` | Rule condition: `any` (any string) or `all` (all strings). (Required)              |
| `-s, --strings`   | List of strings to search for. (Required)                                          |
| `-b, --base64`    | Indexes of strings that should be searched in base64 (starting from 0). (Optional) |
| `-x, --hex`       | Indexes of strings that should also be searched in hexadecimal (starting from 0). (Optional) |

### 🔹 Usage Example

Generate a YARA rule to search for the strings `malware` and `trojan`, where `trojan` should be searched in base64 and `malware` in hexadecimal:

```sh
python yara_generator.py -o malware_rules.yar -c any -s malware trojan -b 1 -x 0
```

This will generate a `malware_rules.yar` file containing:

```yara
rule malware_rules
{
    strings:
      $string1 = "malware" nocase
      $hex_string1 = { 6D 61 6C 77 61 72 65 }
      $string2 = "trojan" base64
    condition:
      any of them
}
```

## 📝 License

This project is under the MIT license. Feel free to use and modify it as needed.

---

Created by [Noslia](https://github.com/ailsongabriel).

