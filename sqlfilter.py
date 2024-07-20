
import os
import glob

output_dir = "dump1"
output_file = "DTADUMP.txt"

files = glob.glob(os.path.join(output_dir, '**/*.csv'), recursive=True)
seen_lines = set()
with open(output_file, 'w') as outfile:
    for fname in files:
        with open(fname) as infile:
            for line in infile:
                stripped_line = line.strip()
                if stripped_line and "null" not in stripped_line.lower():
                    if stripped_line not in seen_lines:
                        outfile.write(line)
                        seen_lines.add(stripped_line)

                  
