import argparse

def format_string(s, flag, index):
  if s.startswith('{') and s.endswith('}'):
    return f'$string{index+1} = {s}'
  else:
    return f'$string{index+1} = "{s}" {flag}'

def yaraGen(strings, condition, output_file):
  defined_strings = "\n      ".join([format_string(s[0], s[1], i) for i, s in enumerate(strings)])

  yara_rule = f"""rule {output_file} 
  {{
    strings:
      {defined_strings}
    condition:
      {condition}
  }}
  """

  try:
    with open(output_file, 'w') as file:
      file.write(yara_rule)
      print(f"YARA rule successfully saved in {output_file}")
  except Exception as e:
    print(f"Error saving the file: {e}")

def main():
  parser = argparse.ArgumentParser(description="YARA rule generator")
  parser.add_argument("-p", "--path", required=True, help="Path of the directory to scan")
  parser.add_argument("-o", "--output", default="StringSearch.yar", help="Output file name")
  parser.add_argument("-c", "--condition", choices=["any", "all"], required=True, help="Rule condition (any or all)")
  parser.add_argument("-s", "--strings", nargs='+', required=True, help="List of strings to search for")
  parser.add_argument("-b", "--base64", nargs='*', default=[], help="List of string indexes to be searched in base64 (0-based index)")
  
  args = parser.parse_args()
  
  condition = "any of them" if args.condition == "any" else "all of them"
  
  strings = [(s, "base64" if str(i) in args.base64 else "nocase") for i, s in enumerate(args.strings)]
  
  yaraGen(strings, condition, args.output)
  
  print("To execute scan with your yara rule, run the following command:")
  print()
  print(f'yara {args.output} -r -s {args.path}')

if __name__ == "__main__":
  main()