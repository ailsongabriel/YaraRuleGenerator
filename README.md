# YARA Rule Generator

This script generates YARA rules based on user-provided strings and allows recursive directory searches.

## 🚀 Features

- Automatic YARA rule generation.
- Supports `any` or `all` conditions.
- Option to search for strings in base64.
- Saves the generated rule in a `.yar` file.
- Displays the command to execute the search with the created rule.

## 📌 Prerequisites

- Python 3.x installed.
- YARA installed and configured on the system.

## 📥 Installation

Clone this repository or download the script manually:

```sh
git clone https://github.com/ailsongabriel/YaraRuleGenerator.git
cd YaraRuleGenerator
```

## ⚙️ Usage

Run the script with the following arguments:

```sh
python yara_generator.py -p <directory> -o <output_file>.yar -c <condition> -s <string1> <string2> ... [-b <base64_indexes>]
```

### 🔹 Arguments

| Parameter         | Description                                                                        |
| ----------------- | ---------------------------------------------------------------------------------- |
| `-p, --path`      | Path of the directory to be scanned. (Required)                                    |
| `-o, --output`    | Output file name. Default: `StringSearch.yar`.                                     |
| `-c, --condition` | Rule condition: `any` (any string) or `all` (all strings). (Required)              |
| `-s, --strings`   | List of strings to search for. (Required)                                          |
| `-b, --base64`    | Indexes of strings that should be searched in base64 (starting from 0). (Optional) |

### 🔹 Usage Example

Generate a YARA rule to search for the strings `malware` and `trojan`, where `trojan` should be searched in base64:

```sh
python yara_generator.py -p /path/to/directory -o malware_rules.yar -c any -s malware trojan -b 1
```

This will generate a `malware_rules.yar` file containing:

```yara
rule malware_rules
{
    strings:
      $string1 = "malware" nocase
      $string2 = "trojan" base64
    condition:
      any of them
}
```

To execute the search with YARA:

```sh
yara malware_rules.yar -r -s /path/to/directory
```

## 📝 License

This project is under the MIT license. Feel free to use and modify it as needed.

---

Created by [Noslia](https://github.com/ailsongabriel).

